import type {
  OwnedProviderProcessSpawnOptions,
  ProviderProcessLaunch,
  ProviderProcessSnapshot,
  SpawnedOwnedProviderProcess,
} from "./ProviderProcess.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedChildProcess,
  spawnOwnedProviderProcess,
} from "./ProviderProcess.js";
import {
  cleanupOwnedProcessGroup,
  type ProcessCleanupFailure,
} from "./ProcessOwnership.js";
import {
  ProviderStartupDeadline,
  waitForAbortableDelay,
} from "./ProviderDeadline.js";

/** A short-lived command failed its lifecycle or complete-output contract. */
export class OwnedCommandFailure extends Error {
  readonly cleanupResult: ProcessCleanupFailure | undefined;

  constructor(
    readonly reason: "cancelled" | "timeout" | "output-limit" | "process",
    message: string,
    readonly snapshot: ProviderProcessSnapshot | null = null,
    readonly cleanupFailure: string | null = null,
    options?: ErrorOptions & { readonly cleanupResult?: ProcessCleanupFailure },
    readonly resources: readonly string[] = [],
    readonly cleanupOwner?: ProviderProcessSupervisor,
  ) {
    super(message, options);
    this.cleanupResult = options?.cleanupResult;
  }
}

/** Execute a single owned process with independent cleanup and bounded diagnostic retention. */
export const runOwnedCommand = async (
  spawn: OwnedProviderProcessSpawnOptions,
  limits: {
    readonly timeoutMs: number;
    readonly diagnosticBytes: number;
    /** Accept an ordinary nonzero exit after output closes without other process errors. */
    readonly acceptNonZeroExit?: boolean;
  },
  options:
    | {
        readonly signal?: AbortSignal;
        readonly supervision?: "process-group";
        readonly launcher?: (
          input: OwnedProviderProcessSpawnOptions,
        ) => Promise<SpawnedOwnedProviderProcess>;
      }
    | {
        readonly signal?: AbortSignal;
        /**
         * Supervise a REA-owned helper that creates no descendant processes
         * through its live child handle, without process-group token inspection.
         */
        readonly supervision: "direct-child";
        readonly launcher?: never;
      } = {},
): Promise<ProviderProcessSnapshot> => {
  const callerSignal = options.signal ?? spawn.signal;
  if (callerSignal?.aborted)
    throw new OwnedCommandFailure(
      "cancelled",
      "Command cancelled before launch.",
    );
  const deadline = new ProviderStartupDeadline(limits.timeoutMs, callerSignal);
  try {
    return await collectOwnedCommand(
      spawn,
      limits,
      options.supervision === "direct-child"
        ? launchDirectChild
        : processGroupLauncher(options.launcher ?? spawnOwnedProviderProcess),
      deadline,
      callerSignal,
    );
  } finally {
    deadline.dispose();
  }
};

/** One supervised launch and the resources retained if its cleanup fails. */
interface OwnedCommandLaunch {
  readonly launch: Extract<
    ProviderProcessLaunch,
    { ownsProcessLifetime: true }
  >;
  readonly resources: readonly string[];
}

const processGroupLauncher =
  (
    launcher: (
      input: OwnedProviderProcessSpawnOptions,
    ) => Promise<SpawnedOwnedProviderProcess>,
  ) =>
  async (
    input: OwnedProviderProcessSpawnOptions,
  ): Promise<OwnedCommandLaunch> => {
    const launched = await launcher(input);
    return {
      launch: {
        ...launched,
        ownsProcessLifetime: true,
        cleanup:
          launched.cleanup ??
          (() => cleanupOwnedProcessGroup(launched.ownership)),
      },
      resources: [
        `pid:${launched.ownership.leaderPid}`,
        `process-group:${launched.ownership.processGroupId}`,
      ],
    };
  };

const launchDirectChild = async (
  input: OwnedProviderProcessSpawnOptions,
): Promise<OwnedCommandLaunch> => {
  const child = await spawnOwnedChildProcess(input);
  // Without a cleanup capability the supervisor escalates TERM to KILL through
  // this handle, which Node refuses to signal once the child has been reaped.
  return {
    launch: { process: child, ownsProcessLifetime: true },
    resources: [`pid:${String(child.pid)}`],
  };
};

const collectOwnedCommand = async (
  spawn: OwnedProviderProcessSpawnOptions,
  limits: {
    readonly diagnosticBytes: number;
    /** Accept an ordinary nonzero exit after output closes without other process errors. */
    readonly acceptNonZeroExit?: boolean;
  },
  launcher: (
    input: OwnedProviderProcessSpawnOptions,
  ) => Promise<OwnedCommandLaunch>,
  deadline: ProviderStartupDeadline,
  callerSignal?: AbortSignal,
): Promise<ProviderProcessSnapshot> => {
  const signal = deadline.signal;
  let launched: OwnedCommandLaunch;
  try {
    launched = await launcher({
      ...spawn,
      signal,
    });
  } catch (cause: unknown) {
    const interruption = deadline.interruption;
    if (interruption !== undefined)
      throw new OwnedCommandFailure(
        interruption,
        interruption === "cancelled"
          ? "Command cancelled during ownership preparation."
          : "Command deadline elapsed during ownership preparation.",
        null,
        null,
        { cause },
      );
    throw cause;
  }
  let exceeded = false;
  let processFailure: string | undefined;
  const supervisor = new ProviderProcessSupervisor(launched.launch, {
    maxDiagnosticBytes: limits.diagnosticBytes,
    onDiagnostic: (event) => {
      if (event.type === "output" && event.truncated === true) exceeded = true;
      if (event.type === "error") processFailure = event.message;
    },
  });
  let failure: OwnedCommandFailure | undefined;
  try {
    while (!(await supervisor.waitForOutputClose(10))) {
      const interruption = deadline.interruption;
      if (interruption !== undefined)
        throw new OwnedCommandFailure(
          interruption,
          interruption === "cancelled"
            ? "Command cancelled."
            : "Command deadline elapsed.",
        );
      if (exceeded)
        throw new OwnedCommandFailure(
          "output-limit",
          "Command diagnostic output exceeded its complete-output budget.",
        );
      if (processFailure !== undefined)
        throw new OwnedCommandFailure("process", processFailure);
      await waitForAbortableDelay(25, signal);
    }
    const snapshot = supervisor.snapshot();
    const interruption = deadline.interruption;
    if (interruption !== undefined)
      throw new OwnedCommandFailure(
        interruption,
        interruption === "cancelled"
          ? "Command cancelled."
          : "Command deadline elapsed.",
        snapshot,
      );
    if (exceeded)
      throw new OwnedCommandFailure(
        "output-limit",
        "Command diagnostic output exceeded its complete-output budget.",
        snapshot,
      );
    const acceptedNonzeroExit =
      limits.acceptNonZeroExit === true &&
      snapshot.exitCode !== null &&
      snapshot.exitCode !== undefined &&
      snapshot.exitCode !== 0 &&
      snapshot.signal === null;
    if (
      processFailure !== undefined ||
      ((snapshot.exitCode !== 0 || snapshot.signal !== null) &&
        !acceptedNonzeroExit)
    )
      throw new OwnedCommandFailure(
        "process",
        processFailure ??
          "Command failed; inspect its exit status and diagnostics.",
        snapshot,
      );
  } catch (cause: unknown) {
    failure =
      cause instanceof OwnedCommandFailure
        ? cause
        : new OwnedCommandFailure(
            "process",
            "Command collection failed.",
            null,
            null,
            { cause },
          );
  }
  const stopped = await supervisor.stop();
  const snapshot = supervisor.snapshot();
  if (stopped.status === "incomplete")
    throw new OwnedCommandFailure(
      failure?.reason ?? "process",
      failure?.message ?? "Command cleanup failed.",
      snapshot,
      stopped.reason,
      {
        ...(failure === undefined ? {} : { cause: failure }),
        ...(stopped.cleanupResult === undefined
          ? {}
          : { cleanupResult: stopped.cleanupResult }),
      },
      [
        spawn.runId,
        ...(spawn.cwd === undefined ? [] : [spawn.cwd]),
        ...launched.resources,
      ],
      supervisor,
    );
  if (failure !== undefined)
    throw new OwnedCommandFailure(
      failure.reason,
      failure.message,
      snapshot,
      failure.cleanupFailure,
      {
        cause: failure,
        ...(failure.cleanupResult === undefined
          ? {}
          : { cleanupResult: failure.cleanupResult }),
      },
      failure.resources,
    );
  if (callerSignal?.aborted)
    throw new OwnedCommandFailure("cancelled", "Command cancelled.", snapshot);
  return snapshot;
};

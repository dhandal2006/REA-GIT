import type { InspectWebNetworkCaptureInput } from "../../domain/webNetworkCapture.js";

/** Format-specific process profile keeps mature upstream code behind a replaceable adapter seam. */
export interface HistoricalCaptureFormatAdapter {
  readonly format: InspectWebNetworkCaptureInput["format"];
  readonly identity: {
    readonly id: string;
    readonly name: string;
    readonly version: string;
  };
  /**
   * REA's own decoder helpers create no descendants and are supervised through
   * their child handle; external tools keep token-verified process groups. A
   * command that requests a memory limit runs under the owned launcher, the
   * only one that enforces it.
   */
  readonly supervision: "direct-child" | "process-group";
  /** `memoryLimitBytes` requests an enforced commit limit for the decoder process tree. */
  command(
    requestPath: string,
    runtimePath: string,
  ): Promise<{
    command: string;
    arguments: readonly string[];
    memoryLimitBytes?: number;
  }>;
}

// 统一错误码（API 与 CLI 共用）
export type ErrorCode =
  | "INVALID_ARGUMENT"
  | "NOT_FOUND"
  | "UNSUPPORTED_FORMAT"
  | "CORRUPT_FILE"
  | "LIMIT_EXCEEDED"
  | "PATH_OUT_OF_SCOPE"
  | "FILE_CHANGED"
  | "INTERNAL";

export class ApiError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message: string,
    public readonly httpStatus: number = 400,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = "ApiError";
  }
}

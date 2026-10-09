// Minimal ClickHouse HTTP interface client. Values reach the server only as
// typed query parameters (param_<name>) or JSONEachRow bodies, never spliced
// into SQL text; Semgrep rule rg-clickhouse-interpolated-sql enforces this.

export interface ClickHouseHttpOptions {
  readonly url: string;
  readonly timeoutMs: number;
  /** Injected in tests to prove which requests are (not) made. */
  readonly fetch?: typeof fetch;
}

export class ClickHouseError extends Error {
  override readonly name = "ClickHouseError";
}

const SETTINGS: Readonly<Record<string, string>> = {
  date_time_input_format: "best_effort",
  output_format_json_quote_64bit_integers: "0",
  wait_end_of_query: "1",
};

export class ClickHouseHttp {
  readonly #url: string;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(options: ClickHouseHttpOptions) {
    this.#url = options.url;
    this.#timeoutMs = options.timeoutMs;
    this.#fetch = options.fetch ?? fetch;
  }

  /** Executes one statement passed in the request body. */
  async exec(sql: string, params: Readonly<Record<string, string>> = {}): Promise<string> {
    return this.#post(this.#endpoint(params), sql);
  }

  /** Runs a SELECT and decodes JSONEachRow output. */
  async rows<T>(sql: string, params: Readonly<Record<string, string>> = {}): Promise<T[]> {
    const endpoint = this.#endpoint(params);
    endpoint.searchParams.set("default_format", "JSONEachRow");
    const text = await this.#post(endpoint, sql);
    return text
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as T);
  }

  /** Sends rows as a JSONEachRow body; insertSql must end with FORMAT JSONEachRow. */
  async insert(insertSql: string, rows: readonly object[]): Promise<void> {
    if (rows.length === 0) {
      return;
    }
    const endpoint = this.#endpoint({});
    endpoint.searchParams.set("query", insertSql);
    await this.#post(endpoint, rows.map((row) => JSON.stringify(row)).join("\n"));
  }

  async version(): Promise<string> {
    const [row] = await this.rows<{ version: string }>("SELECT version() AS version");
    if (!row) {
      throw new ClickHouseError("version query returned no row");
    }
    return row.version;
  }

  #endpoint(params: Readonly<Record<string, string>>): URL {
    const endpoint = new URL(this.#url);
    for (const [key, value] of Object.entries(SETTINGS)) {
      endpoint.searchParams.set(key, value);
    }
    for (const [key, value] of Object.entries(params)) {
      endpoint.searchParams.set(`param_${key}`, value);
    }
    return endpoint;
  }

  async #post(endpoint: URL, body: string): Promise<string> {
    let response: Response;
    try {
      // redirect: "error" keeps a validated loopback endpoint from being redirected elsewhere.
      response = await this.#fetch(endpoint, { method: "POST", body, redirect: "error", signal: AbortSignal.timeout(this.#timeoutMs) });
    } catch (error) {
      throw new ClickHouseError(`request failed: ${(error as Error).message}`);
    }
    const text = await response.text();
    if (!response.ok) {
      throw new ClickHouseError(`HTTP ${response.status}: ${text.slice(0, 300)}`);
    }
    return text;
  }
}

// Must not fire: an unrelated client's exec() method is not a shell.
export async function createSchema(http: { exec(sql: string): Promise<string> }) {
  await http.exec("CREATE DATABASE IF NOT EXISTS router_guard");
}

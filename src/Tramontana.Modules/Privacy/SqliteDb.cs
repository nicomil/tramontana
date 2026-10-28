using Microsoft.Data.Sqlite;

namespace Tramontana.Modules.Privacy;

/// <summary>
/// Small wrapper over Microsoft.Data.Sqlite for browser databases. Pooling
/// is off, so no file handle stays open after Dispose (a pooled handle would
/// keep the browser from opening its profile).
/// </summary>
public sealed class SqliteDb : IDisposable
{
    private readonly SqliteConnection _connection;
    public string Path { get; }
    /// <summary>False when the database was read as an immutable snapshot (newest rows in -wal not seen).</summary>
    public bool ReadsLatest { get; }

    private SqliteDb(SqliteConnection connection, string path, bool readsLatest)
    {
        _connection = connection;
        Path = path;
        ReadsLatest = readsLatest;
    }

    /// <summary>
    /// Opens read-only, seeing the changes still in the -wal file. If the
    /// browser holds a lock, falls back to reading the main file as it is.
    /// </summary>
    public static SqliteDb? OpenReadOnly(string path)
    {
        if (!File.Exists(path)) return null;
        var normal = Open(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false, DefaultTimeout = 1 }.ToString());
        if (normal is not null && Probe(normal)) return new SqliteDb(normal, path, readsLatest: true);
        normal?.Dispose();
        var uri = "file:///" + path.Replace('\\', '/').Replace("%", "%25").Replace("#", "%23").Replace("?", "%3F") + "?immutable=1";
        var immutable = Open(new SqliteConnectionStringBuilder { DataSource = uri, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        if (immutable is not null && Probe(immutable)) return new SqliteDb(immutable, path, readsLatest: false);
        immutable?.Dispose();
        return null;
    }

    public static SqliteDb? OpenReadWrite(string path)
    {
        if (!File.Exists(path)) return null;
        var connection = Open(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false, DefaultTimeout = 2 }.ToString());
        return connection is null ? null : new SqliteDb(connection, path, readsLatest: true);
    }

    private static SqliteConnection? Open(string connectionString)
    {
        try
        {
            var c = new SqliteConnection(connectionString);
            c.Open();
            return c;
        }
        catch (SqliteException) { return null; }
    }

    private static bool Probe(SqliteConnection c)
    {
        try
        {
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT count(*) FROM sqlite_master";
            cmd.ExecuteScalar();
            return true;
        }
        catch (SqliteException) { return false; }
    }

    public bool TableExists(string table)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$t";
        cmd.Parameters.AddWithValue("$t", table);
        return cmd.ExecuteScalar() is not null;
    }

    public long? Count(string table, string? where = null)
    {
        if (!TableExists(table)) return null;
        try
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = $"SELECT count(*) FROM \"{table.Replace("\"", "\"\"")}\"{(where is null ? "" : " WHERE " + where)}";
            return Convert.ToInt64(cmd.ExecuteScalar());
        }
        catch (SqliteException) { return null; }
    }

    public bool Execute(string sql)
    {
        try
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
            return true;
        }
        catch (SqliteException) { return false; }
    }

    /// <summary>Runs the statements in one transaction; nothing changes if one fails.</summary>
    public bool ExecuteAll(IEnumerable<string> statements)
    {
        using var transaction = _connection.BeginTransaction();
        foreach (var sql in statements)
        {
            using var cmd = _connection.CreateCommand();
            cmd.Transaction = transaction;
            cmd.CommandText = sql;
            try { cmd.ExecuteNonQuery(); }
            catch (SqliteException) { transaction.Rollback(); return false; }
        }
        transaction.Commit();
        return true;
    }

    /// <summary>
    /// A complete standalone copy made by SQLite (VACUUM INTO), including the
    /// changes still in the -wal file, read back before returning true.
    /// </summary>
    public bool Snapshot(string destination)
    {
        if (!ReadsLatest) return false;
        long tables = TableCount();
        if (tables < 0 || !Execute($"VACUUM INTO '{destination.Replace("'", "''")}'")) return false;
        using var copy = OpenReadOnly(destination);
        return copy is not null && copy.ReadsLatest && copy.TableCount() == tables;
    }

    /// <summary>Number of tables, or -1 when the schema cannot be read.</summary>
    public long TableCount()
    {
        try
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT count(*) FROM sqlite_master WHERE type='table'";
            return Convert.ToInt64(cmd.ExecuteScalar());
        }
        catch (SqliteException) { return -1; }
    }

    public void Dispose() => _connection.Dispose();
}

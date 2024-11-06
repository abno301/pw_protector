using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class MasterPasswordService
{
    private const string MasterPasswordHashFile = "master_hash.txt";
    public string MasterPasswordHash;

    public bool VerifyMasterPassword(string masterPassword)
    {
        if (!File.Exists(MasterPasswordHashFile))
        {
            SetMasterPassword(masterPassword);
            return true;
        }

        var storedHash = File.ReadAllText(MasterPasswordHashFile);
        MasterPasswordHash = storedHash;

        return Hash(masterPassword) == storedHash;
    }

    private void SetMasterPassword(string masterPassword)
    {
        var hashedPassword = Hash(masterPassword);
        if (hashedPassword != null)
        {
            MasterPasswordHash = hashedPassword;
        }

        File.WriteAllText(MasterPasswordHashFile, hashedPassword);
    }

    private string Hash(string input)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(bytes);
    }
}

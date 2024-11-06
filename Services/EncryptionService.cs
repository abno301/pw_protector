using System;
using System.Security.Cryptography;
using System.Text;

public class EncryptionService
{
    private readonly byte[] _key;

    public EncryptionService(string masterPasswordHash)
    {
        _key = new Rfc2898DeriveBytes(masterPasswordHash, Encoding.UTF8.GetBytes("unique_salt"), 10000)
            .GetBytes(32);
    }

    public string Encrypt(string plainText)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.GenerateIV();
        var iv = aes.IV;

        using var encryptor = aes.CreateEncryptor();
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        return Convert.ToBase64String(iv) + ":" + Convert.ToBase64String(encryptedBytes);
    }

    public string Decrypt(string cipherText)
    {
        var parts = cipherText.Split(':');
        var iv = Convert.FromBase64String(parts[0]);
        var encryptedBytes = Convert.FromBase64String(parts[1]);

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        var decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

        return Encoding.UTF8.GetString(decryptedBytes);
    }
}

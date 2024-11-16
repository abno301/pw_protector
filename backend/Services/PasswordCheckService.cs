using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public class PasswordCheckService
{
    private const string ApiUrl = "https://api.pwnedpasswords.com/range/";

    public static async Task<bool> IsPasswordPwnedAsync(string password)
    {
        var sha1Hash = HashPassword(password);
        var prefix = sha1Hash.Substring(0, 5);
        var suffix = sha1Hash.Substring(5).ToUpper();

        using var httpClient = new HttpClient();
        var response = await httpClient.GetStringAsync(ApiUrl + prefix);

        return response.Contains(suffix);
    }

    private static string HashPassword(string password)
    {
        using var sha1 = SHA1.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = sha1.ComputeHash(bytes);
        return BitConverter.ToString(hash).Replace("-", "");
    }
}

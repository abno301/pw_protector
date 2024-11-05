using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Text;

namespace pw_p_api
{
    public class WeatherForecast
    {
        public DateOnly Date { get; set; }

        public int TemperatureC { get; set; }

        public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);

        public string? Summary { get; set; }
    }

    public class PasswordManager
    {

        static void Main()
        {
            // Example: Set or verify master password at startup
            Console.WriteLine("Welcome to Password Manager");
            Console.Write("Enter your master password: ");
            var masterPassword = Console.ReadLine();

            var masterService = new MasterPasswordService();
            if (!masterService.VerifyMasterPassword(masterPassword))
            {
                Console.WriteLine("Invalid password.");
                return;
            }

            // console log new password hash
            Console.WriteLine("Password hash: " + masterService.MasterPasswordHash);

            var encryptionService = new EncryptionService(masterService.MasterPasswordHash);

            var encrypted = encryptionService.Encrypt("mySecretPassword");

            Console.WriteLine("Encrypted: " + encrypted);


            var decrypted = encryptionService.Decrypt(encrypted);

            Console.WriteLine("Decrypted: " + decrypted);

            //  var site = "example.com";
            //
            //  // var vault = new VaultService(masterPassword);
            //  VaultService.AddAccount(site, "user@example.com", encryptionService.Encrypt("mySecretPassword"));
            //
            // var account = VaultService.GetAccount(site);
            //
            // if (account == null)
            // {
            //     return;
            // }
            //
            // // Here you would decrypt the password if necessary
            // Console.WriteLine($"Site: {account["Site"]}");
            // Console.WriteLine($"Username: {account["Username"]}");
            // Console.WriteLine($"Password: {encryptionService.Decrypt(account["Password"].ToString())}");

            // Console.Write("Enter a password to check: ");
            // var password = Console.ReadLine();
            //
            // bool isPwned = await PasswordCheckService.IsPasswordPwnedAsync(password);
            // if (isPwned)
            // {
            //     Console.WriteLine("This password has been pwned in data breaches.");
            // }
            // else
            // {
            //     Console.WriteLine("This password has not been found in any data breaches.");
            // }

            // Console.Write("Enter a password to check its strength: ");
            // var password = Console.ReadLine();
            //
            // var strength = PasswordStrengthChecker.CheckPasswordStrength(password);
            // Console.WriteLine($"Password Strength: {strength}");
        }
    }

    // Manages hashing and storing the master password
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

    // Encrypts and decrypts passwords
    public class EncryptionService
    {
        private readonly byte[] _key;

        public EncryptionService(string masterPasswordHash)
        {
            // Derive a 256-bit key from the master password
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

    // VaultService class
    public class VaultService
    {
        private const string VaultFile = "vault.json";

        // public VaultService(string masterPassword)
        // {
        //     _encryptionService = new EncryptionService(masterPassword);
        // }

        public static void AddAccount(string site, string username, string passwordEnc)
        {
            // var encryptedPassword = _encryptionService.Encrypt(password);
            var account = new { Site = site, Username = username, Password = passwordEnc };

            List<dynamic> accounts;
            if (File.Exists(VaultFile))
            {
                var json = File.ReadAllText(VaultFile);
                accounts = JsonSerializer.Deserialize<List<dynamic>>(json) ?? new List<dynamic>();
            }
            else
            {
                accounts = new List<dynamic>();
            }

            accounts.Add(account);
            var updatedJson = JsonSerializer.Serialize(accounts, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(VaultFile, updatedJson);

            Console.WriteLine($"Account for {site} added.");
        }

        //get account data
        public static Dictionary<string, object>? GetAccount(string site)
        {
            if (!File.Exists(VaultFile))
            {
                Console.WriteLine("No accounts found.");
                return null;
            }

            var json = File.ReadAllText(VaultFile);
            var accounts = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(json);

            var account = accounts.FirstOrDefault(a => a["Site"].ToString() == site);
            if (account == null)
            {
                Console.WriteLine($"No account found for {site}.");
                return null;
            }

            return account;
        }
    }

    public class PasswordCheckService
    {
        private const string ApiUrl = "https://api.pwnedpasswords.com/range/";

        public static async Task<bool> IsPasswordPwnedAsync(string password)
        {
            // Step 1: Hash the password using SHA-1
            var sha1Hash = HashPassword(password);

            // Step 2: Get the hash prefix and suffix
            var prefix = sha1Hash.Substring(0, 5);
            var suffix = sha1Hash.Substring(5).ToUpper();

            // Step 3: Call the Have I Been Pwned API
            using var httpClient = new HttpClient();
            var response = await httpClient.GetStringAsync(ApiUrl + prefix);

            // Step 4: Check if the password suffix is present in the response
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

    public class PasswordStrengthChecker
    {
        public static string CheckPasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return "Password cannot be empty.";
            }

            int score = 0;

            // Check length
            if (password.Length >= 8) score++; // Length at least 8
            if (password.Length >= 12) score++; // Length at least 12

            // Check for different character types
            if (Regex.IsMatch(password, @"[a-z]") && Regex.IsMatch(password, @"[A-Z]"))
                score++; // Lowercase letters and uppercase letters
            if (Regex.IsMatch(password, @"[0-9]")) score++; // Numbers
            if (Regex.IsMatch(password, @"[!@#$%^&*(),.?""{}|<>]")) score++; // Special characters

            // Check for common patterns (this can be improved with a more comprehensive list)
            bool hasBadEnding = Regex.IsMatch(password, @"[!@#$%^&*(),.?""{}|<>]$|[0-9]$");
            bool isCapitalizationLimited = Regex.IsMatch(password, @"^[A-Z][a-z]+$");
            bool hasRepetitiveCharacters = Regex.IsMatch(password, @"(.)\1{2,}");

            if (!hasBadEnding && !isCapitalizationLimited && !hasRepetitiveCharacters) score += 2;

            // Evaluate the score
            return score switch
            {
                0 => "Very Weak",
                1 => "Weak",
                2 => "Moderate",
                3 => "Moderate",
                4 => "Strong",
                5 => "Strong",
                6 => "Very Strong",
                7 => "Excellent",
                _ => "Invalid Password" // For unexpected cases
            };
        }

        public static string GeneratePassword(bool useUppercase, bool useLowercase, bool useSymbols, bool useNumbers,
            int length)
        {
            if (length <= 0)
            {
                throw new ArgumentException("Password length must be greater than 0.");
            }

            // Define character sets
            const string uppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lowercaseLetters = "abcdefghijklmnopqrstuvwxyz";
            const string symbols = "!@#$%^&*(),.?\"{}|<>[]";
            const string numbers = "0123456789";

            // Build the character pool based on options
            StringBuilder characterPool = new StringBuilder();
            characterPool.Append(lowercaseLetters);

            if (useUppercase) characterPool.Append(uppercaseLetters);
            if (useSymbols) characterPool.Append(symbols);
            if (useNumbers) characterPool.Append(numbers);

            // Generate password using a secure random generator
            StringBuilder password = new StringBuilder();
            Random random = new Random();

            for (int i = 0; i < length; i++)
            {
                int randomIndex = random.Next(characterPool.Length);
                password.Append(characterPool[randomIndex]);
            }

            string passwordString = password.ToString();

            return passwordString;
        }
    }
}

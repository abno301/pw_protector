using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls("http://0.0.0.0:5144");

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// set master password
app.MapPost("/masterPassword", (PasswordsRequest masterPasswordRequest) => {
        Console.WriteLine(masterPasswordRequest.MasterPassword);

        var masterService = new MasterPasswordService();
         if (!masterService.VerifyMasterPassword(masterPasswordRequest.MasterPassword))
         {
             Console.WriteLine("Invalid password.");
             return Results.BadRequest("invalid master password");         }

         Console.WriteLine("Password hash: " + masterService.MasterPasswordHash);
         
         return Results.Ok(new { MasterPasswordHash = masterService.MasterPasswordHash });
    })
    .WithName("CreateMasterPassword")
    .WithOpenApi();

// add password to password protector
app.MapPost("/password", ([FromBody]CreatePasswordRequest request) => {
        Console.WriteLine(request);

        var masterService = new MasterPasswordService();
         if (!masterService.VerifyMasterPassword(request.MasterPassword))
         {
             Console.WriteLine("Invalid password.");
             return Results.BadRequest("invalid master password");
         }
         
         var encryptionService = new EncryptionService(masterService.MasterPasswordHash);
         
         var encrypted = encryptionService.Encrypt(request.Password);

         Console.WriteLine("Encrypted: " + encrypted);


         // var decrypted = encryptionService.Decrypt(encrypted);
         //
         // Console.WriteLine("Decrypted: " + decrypted);
         
        return Results.Ok(new { Encrypted = encrypted });
    })
    .WithName("AddPassword")
    .WithOpenApi();

// get all passwords from master password
app.MapGet("/password", ([FromBody]PasswordsRequest request) => {
        Console.WriteLine(request);

        var masterService = new MasterPasswordService();
         if (!masterService.VerifyMasterPassword(request.MasterPassword))
         {
             Console.WriteLine("Invalid password.");
             return Results.BadRequest("invalid master password");
         }
         
         var encryptionService = new EncryptionService(masterService.MasterPasswordHash);


         // var decrypted = encryptionService.Decrypt(encrypted);
         //
         // Console.WriteLine("Decrypted: " + decrypted);
         
        return Results.Ok();
    })
    .WithName("GetAllPasswords")
    .WithOpenApi();

// get specific password
app.MapGet("/password/{passwordId}", ([FromBody]PasswordsRequest request, string passwordId) => {
        Console.WriteLine(request);

        var masterService = new MasterPasswordService();
        if (!masterService.VerifyMasterPassword(request.MasterPassword))
        {
            Console.WriteLine("Invalid password.");
            return Results.BadRequest("invalid master password");
        }
         
        var encryptionService = new EncryptionService(masterService.MasterPasswordHash);


        // var decrypted = encryptionService.Decrypt(encrypted);
        //
        // Console.WriteLine("Decrypted: " + decrypted);
         
        return Results.Ok();
    })
    .WithName("GetPasswordById")
    .WithOpenApi();


app.Run();

public record CreatePasswordRequest(string Password, string MasterPassword);

public record PasswordsRequest(string MasterPassword);
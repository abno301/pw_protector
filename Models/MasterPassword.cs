using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace MyWebApiApp.Models;

public class MasterPassword
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; }
    
    public string Username { get; set; }

    public string PasswordHash { get; set; }
}

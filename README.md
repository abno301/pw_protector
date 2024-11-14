# pw_protector

### Docker compose
zazenes:
docker compose up --build

vgasnes:
docker compose down


### REST API:

1. **Get all users passwords** 
`POST` http://localhost:5144/password/jernejtest  
**Request Body example:**
```json 
{
   "Username": "jernejtest",
   "MasterPassword": "mysecretpassword"
}
```

2. **Create user** 
`POST` http://localhost:5144/masterPassword  
   **Request Body example:**
```json 
{
   "Username": "jernejtest",
   "MasterPassword": "mysecretpassword"
}
```

3. **Add password to user**
`POST` http://localhost:5144/password/password  
   **Request Body example:**
```json 
{
  "Username": "jernejtest",
  "MasterPassword": "mysecretpassword",
  "Password": "password123",
  "Description": "facebook"
}
```
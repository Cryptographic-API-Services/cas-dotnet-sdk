## Password Hashers
- Argon2 Hash

|Method|50 hashes in seconds (s)|
|---|---|
| CAS Argon2 HashPasswordsThread  | 00.2123454  |
| CAS Argon2 HashPassword | 00.3589130 |
```csharp
Argon2Wrappper wrapper = new Argon2Wrappper();
string myPassword = "1230912380912809askljddkjaskjld";
List<string> strings = new List<string>();
for (int i = 0; i < 50; i++)
{
    strings.Add(myPassword);
}
string[] hashed = wrapper.HashPasswordsThread(strings.ToArray());
```

enum JellyInternalStatus
{
  SUCCES = 0,
  NO_SPACE_LEFT = 1,
  STORAGE_UNITIALIZED = 2,
  INVALID_REQUEST = 3
}

struct ClientProof
{
  1:string user;
}

struct HashStatus
{
  1:string hash;
  2:JellyInternalStatus status;
}

service JellyInternal
{
  JellyInternalStatus prepareAddPart(1:string id, 2:i64 size, 3:ClientProof client);
  JellyInternalStatus addPart(1: string salt, 2:string id, 3:string file, 4:ClientProof client);
  JellyInternalStatus removePart(1:string id, 2:ClientProof client);
  HashStatus hashPart(1:string id, 2:string salt, 3:ClientProof client);
}

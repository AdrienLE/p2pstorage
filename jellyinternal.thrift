enum JellyInternalStatus
{
  SUCCES = 0,
  NO_SPACE_LEFT = 1,
  STORAGE_UNITIALIZED = 2,
  INVALID_REQUEST = 3,
  NO_SUCH_FILE = 4,
  YOU_DONT_HAVE_SPACE = 5
}

struct ClientProof
{
  1:string user;
  2:string signature;
}

struct HashStatus
{
  1:string hash;
  2:JellyInternalStatus status;
}

struct FileStatus
{
  1:string content;
  2:JellyInternalStatus status;
}

service JellyInternal
{
  JellyInternalStatus prepareAddPart(1:string id, 2:i64 size, 3:ClientProof client, 4:i64 total_size);
  JellyInternalStatus addPart(1: string salt, 2:string id, 3:string file, 4:ClientProof client, 5:i64 total_size);
  JellyInternalStatus removePart(1:string id, 2:ClientProof client);
  HashStatus hashPart(1:string id, 2:string salt, 3:ClientProof client);
  FileStatus getFile(1:string id, 2:ClientProof client);
}

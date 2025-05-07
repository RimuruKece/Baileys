import { Mutex } from 'async-mutex'
import { mkdir, readFile, stat, unlink, writeFile } from 'fs/promises'
import { join } from 'path'
import { proto } from '../../WAProto'
import { AuthenticationCreds, AuthenticationState, SignalDataTypeMap } from '../Types'
import { initAuthCreds } from './auth-utils'
import { BufferJSON } from './generics'
import mongoose, { Connection, Document, Model, Schema } from "mongoose";

// We need to lock files due to the fact that we are using async functions to read and write files
// https://github.com/WhiskeySockets/Baileys/issues/794
// https://github.com/nodejs/node/issues/26338
// Use a Map to store mutexes for each file path
const fileLocks = new Map<string, Mutex>()

// Get or create a mutex for a specific file path
const getFileLock = (path: string): Mutex => {
	let mutex = fileLocks.get(path)
	if(!mutex) {
		mutex = new Mutex()
		fileLocks.set(path, mutex)
	}

	return mutex
}

/**
 * Mongo-auth state hook for Baileys using Mongoose.
 * @param mongo - Mongoose Connection instance or MongoDB URI string
 * @param collectionName - Collection name / model collectionName
 */
export async function useMongoAuthState(
  mongo: Connection | string,
  collectionName: string
) {
  // Resolve connection
  const conn: Connection =
    typeof mongo === "string"
      ? await mongoose.createConnection(mongo).asPromise()
      : mongo;

  // Define schema & model
  interface AuthDoc extends Document {
    name: string;
    data: string;
    expireAt?: Date;
  }

  const AuthSchema = new Schema<AuthDoc>(
    {
      name: { type: String, required: true, unique: true },
      data: { type: String, required: true },
      expireAt: {
        type: Date,
        default: undefined,
        index: { expireAfterSeconds: 0 },
      },
    },
    { collection: collectionName }
  );

  const Auth: Model<AuthDoc> =
    conn.models[collectionName] || conn.model<AuthDoc>(collectionName, AuthSchema);

  // Helpers
  async function readData(name: string): Promise<any | null> {
    const doc = await Auth.findOne({ name }).lean();
    if (!doc) return null;
    return JSON.parse(doc.data, BufferJSON.reviver);
  }

  async function writeData(name: string, data: any): Promise<void> {
    const payload: Partial<AuthDoc> = {
      data: JSON.stringify(data, BufferJSON.replacer),
    };

    if (name !== "creds") {
      payload.expireAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    }

    await Auth.updateOne(
      { name },
      { $set: payload },
      { upsert: true }
    ).exec();
  }

  async function removeData(name: string): Promise<void> {
    await Auth.deleteOne({ name }).exec();
  }

  // Initialize credentials
  let creds: AuthenticationCreds = await readData("creds");
  if (!creds) {
    creds = initAuthCreds();
    await writeData("creds", creds);
  }

  return {
    state: {
      creds,
      keys: {
        get: async (type: string, ids: string[]) => {
          const data: Record<string, any> = {};
          await Promise.all(
            ids.map(async (id) => {
              const raw = await readData(`${type}-${id}`);
              data[id] =
                type === "app-state-sync-key" && raw
                  ? proto.Message.AppStateSyncKeyData.fromObject(raw)
                  : raw;
            })
          );
          return data;
        },
        set: async (keyData) => {
          const tasks: Promise<void>[] = [];
          for (const category of Object.keys(keyData)) {
            for (const id of Object.keys(keyData[category])) {
              const value = keyData[category][id];
              const fileName = `${category}-${id}`;
              if (value) tasks.push(writeData(fileName, value));
              else tasks.push(removeData(fileName));
            }
          }
          await Promise.all(tasks);
        },
      },
    },
    saveCreds: async () => writeData("creds", creds),
    dropCollection: async () => Auth.collection.drop(),
  };
}

/**
 * stores the full authentication state in a single folder.
 * Far more efficient than singlefileauthstate
 *
 * Again, I wouldn't endorse this for any production level use other than perhaps a bot.
 * Would recommend writing an auth state for use with a proper SQL or No-SQL DB
 * */
export const useMultiFileAuthState = async(folder: string): Promise<{ state: AuthenticationState, saveCreds: () => Promise<void> }> => {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const writeData = async(data: any, file: string) => {
		const filePath = join(folder, fixFileName(file)!)
		const mutex = getFileLock(filePath)

		return mutex.acquire().then(async(release) => {
			try {
				await writeFile(filePath, JSON.stringify(data, BufferJSON.replacer))
			} finally {
				release()
			}
		})
	}

	const readData = async(file: string) => {
		try {
			const filePath = join(folder, fixFileName(file)!)
			const mutex = getFileLock(filePath)

			return await mutex.acquire().then(async(release) => {
				try {
					const data = await readFile(filePath, { encoding: 'utf-8' })
					return JSON.parse(data, BufferJSON.reviver)
				} finally {
					release()
				}
			})
		} catch(error) {
			return null
		}
	}

	const removeData = async(file: string) => {
		try {
			const filePath = join(folder, fixFileName(file)!)
			const mutex = getFileLock(filePath)

			return mutex.acquire().then(async(release) => {
				try {
					await unlink(filePath)
				} catch{
				} finally {
					release()
				}
			})
		} catch{
		}
	}

	const folderInfo = await stat(folder).catch(() => { })
	if(folderInfo) {
		if(!folderInfo.isDirectory()) {
			throw new Error(`found something that is not a directory at ${folder}, either delete it or specify a different location`)
		}
	} else {
		await mkdir(folder, { recursive: true })
	}

	const fixFileName = (file?: string) => file?.replace(/\//g, '__')?.replace(/:/g, '-')

	const creds: AuthenticationCreds = await readData('creds.json') || initAuthCreds()

	return {
		state: {
			creds,
			keys: {
				get: async(type, ids) => {
					const data: { [_: string]: SignalDataTypeMap[typeof type] } = { }
					await Promise.all(
						ids.map(
							async id => {
								let value = await readData(`${type}-${id}.json`)
								if(type === 'app-state-sync-key' && value) {
									value = proto.Message.AppStateSyncKeyData.fromObject(value)
								}

								data[id] = value
							}
						)
					)

					return data
				},
				set: async(data) => {
					const tasks: Promise<void>[] = []
					for(const category in data) {
						for(const id in data[category]) {
							const value = data[category][id]
							const file = `${category}-${id}.json`
							tasks.push(value ? writeData(value, file) : removeData(file))
						}
					}

					await Promise.all(tasks)
				}
			}
		},
		saveCreds: async() => {
			return writeData(creds, 'creds.json')
		}
	}
}
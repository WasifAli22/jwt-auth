import { InferModel } from 'drizzle-orm';
import { jwt_users } from './schema/user';
export type User = InferModel<typeof jwt_users>  // user types
export type NewUser = InferModel <typeof jwt_users , "insert" > // add new user to db
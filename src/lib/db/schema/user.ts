import { pgTable, serial, text , varchar, boolean, timestamp } from 'drizzle-orm/pg-core';
import { InferModel } from 'drizzle-orm';

export const jwt_users = pgTable('jwt_users', {
  user_id: serial('user_id').primaryKey(),
  name:varchar("name",{length:256}).notNull(),
  email:varchar("email",{length:256}).notNull().unique(),
  password:varchar("password",{length:256}).notNull(),
  created_at: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
});

export type User = InferModel<typeof jwt_users> 
export type NewUser = InferModel <typeof jwt_users , "insert" >
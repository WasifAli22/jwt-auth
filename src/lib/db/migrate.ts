import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import dotenv from 'dotenv';
dotenv.config();

const DATABASE_URL=process.env.POSTGRES_URL;
const runMigrate = async () => {
	if (!DATABASE_URL) {
		throw new Error('DATABASE_URL is not defined');
	}
    const connectionString = DATABASE_URL+ '?sslmode=require' || ''
    const sql = postgres(connectionString, { max: 1 });
	const db = drizzle(sql);
	console.log('⏳ Running migrations...');
    // *** check if the connection is ok or not
    // console.log("connectionString",connectionString)
    // res like this = connectionString postgres://default:(some link)/verceldb?sslmode=require

	const start = Date.now();
	await migrate(db, { migrationsFolder: 'drizzle' });

	const end = Date.now();
	console.log(`✅ Migrations completed in ${end - start}ms`);

	process.exit(0);
};

runMigrate().catch((err) => {
	console.error('❌ Migration failed');
	console.error(err);
	process.exit(1);
});

// #### class configuration code is here ####

// const connectionString =
//   process.env.POSTGRES_URL + '?sslmode=require' || '';
// const sql = postgres(connectionString, { max: 1 });
// const db = drizzle(sql);

// migrate(db, { migrationsFolder: 'drizzle' })
//   .then((msg) => {
//     console.log('Migration successful ===> ', msg);
//   })
//   .catch((err) => {
//     console.log('Migration failed ===> ', err);
//   });
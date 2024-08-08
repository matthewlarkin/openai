create table "assistants" (
	"id" integer primary key autoincrement,
	"name" not null unique,
	"description",
	"contents" not null,
	"created" default current_timestamp
);

create table "threads" (
	"id" integer primary key autoincrement,
	"name",
	"description",
	"created" default current_timestamp
);

create table "thread_messages" (
	"id" integer primary key autoincrement,
	"thread" integer references "threads"("id"),
	"participant",
	"contents",
	"created" default current_timestamp
);

create table "customers" (
	"id" integer primary key autoincrement,
	"name" not null,
	"email" not null,
	"phone",
	"description",
	"created" default current_timestamp
);

create table "stripe_customers" (
	"id" integer primary key autoincrement,
	"stripe_id" not null,
	"customer" integer references "people"("id"),
	"created" default current_timestamp
);

create table "documents" (
	"id" integer primary key autoincrement,
	"title",
	"description",
	"filepath" not null,
	"created" default current_timestamp
);



-- Create base records

insert into "assistants" ("name","description","contents") values (
	"Default",
	"The default bare assistant, focused and concise in its reesponses.",
	"You are a helpful assistant, answering succintly without going into lots of detail, unless you are asked to. If you are asked to, please do go into lots of detail! IMPORTANT: do not make things up if you do not know the answer to. Finally, write like one would speak aloud (do not use abbreviations, wherever possible)."
);
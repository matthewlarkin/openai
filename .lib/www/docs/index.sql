set site = sqlpage.read_file_as_text('index.json');
set page = '{
	"title" : "bare / Docs",
	"description" : "Documentation on bare"
}';
select 'dynamic' as component, sqlpage.run_sql('shell.sql') as properties;
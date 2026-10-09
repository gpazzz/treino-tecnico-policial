TREINO TÉCNICO-POLICIAL — V1.2

ACESSO
- Número mecanográfico de 6 dígitos + PIN de 4 a 6 dígitos.
- Primeiro acesso requer código de ativação de 8 dígitos gerado pelo administrador.
- O administrador inicial é o número 202688.
- Código de ativação inicial do administrador: 08827412
- Depois de usado, esse código deixa de funcionar.
- Após 5 tentativas erradas, a conta fica bloqueada durante 15 minutos.
- As sessões duram até 30 dias por dispositivo.

O QUE FAZER AGORA
1. No Supabase > SQL Editor, execute APENAS supabase_access_v1_2.sql.
   Não volte a executar os 8 ficheiros das 368 perguntas.
2. Abra config.js e coloque o Project URL e a anon/public key do Supabase.
3. Publique index.html, app.js, styles.css, config.js, data.js, sw.js, manifest.webmanifest e a pasta assets no GitHub Pages.
4. Entre em “Primeiro acesso / Ativar conta” com:
   Número: 202688
   Código: 08827412
   PIN: escolha o seu PIN pessoal. Recomenda-se 6 dígitos.
5. Depois do login surge o botão ⚙ de Administração. Aí pode adicionar números autorizados, bloquear acessos e repor PIN.

IMPORTANTE
- Não coloque a service_role key no site. Use apenas a anon/public key no config.js.
- As perguntas não ficam em data.js; são entregues pelo Supabase apenas após uma sessão válida.
- O service worker não guarda respostas da API do Supabase em cache.

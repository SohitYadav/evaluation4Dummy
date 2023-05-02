

Endpoints :  

deployed_link/register -> for signing up for the app using email and password. Password will be stored in hashed form.

deployed_link/login   ->  signing in. Password will be decoded and matched with the entered password.

deployed_link/logout  ->  logging put with blacklisting by redis 
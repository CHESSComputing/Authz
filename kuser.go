package main

// module to handle kerberos access
//
// Copyright (c) 2023 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"log"

	srvConfig "github.com/CHESSComputing/golib/config"
	"gopkg.in/jcmturner/gokrb5.v7/client"
	"gopkg.in/jcmturner/gokrb5.v7/config"
	"gopkg.in/jcmturner/gokrb5.v7/credentials"
)

/*
// helper function to extract username from auth-session cookie
func username(r *http.Request) (string, error) {
	if srvConfig.Config.Authz.TestMode {
		return "test", nil
	}
	cookie, err := r.Cookie("auth-session")
	if err != nil {
		return "", err
	}

	//     byteArray := decrypt([]byte(cookie.Value), Config.StoreSecret)
	//     n := bytes.IndexByte(byteArray, 0)
	//     s := string(byteArray[:n])

	s := cookie.Value

	arr := strings.Split(s, "-")
	if len(arr) != 2 {
		msg := "Unable to decript auth-session"
		log.Printf("ERROR: %s", msg)
		return "", errors.New(msg)
	}
	user := arr[0]
	return user, nil
}

// https://github.com/jcmturner/gokrb5/issues/7
func kuserFromCache(cacheFile string) (*credentials.Credentials, error) {
	cfg, err := config.Load(srvConfig.Config.Kerberos.Krb5Conf)
	ccache, err := credentials.LoadCCache(cacheFile)
	client, err := client.NewClientFromCCache(ccache, cfg)
	err = client.Login()
	if err != nil {
		return nil, err
	}
	return client.Credentials, nil

}
*/

// helper function to perform kerberos authentication
func kuser(user, password string) (*credentials.Credentials, error) {
	cfg, err := config.Load(srvConfig.Config.Kerberos.Krb5Conf)
	if err != nil {
		log.Printf("reading krb5.conf failes, error %v\n", err)
		return nil, err
	}
	client := client.NewClientWithPassword(user, srvConfig.Config.Kerberos.Realm, password, cfg, client.DisablePAFXFAST(true))
	err = client.Login()
	if err != nil {
		log.Printf("client login fails, error %v\n", err)
		return nil, err
	}
	return client.Credentials, nil
}

/*
// authentication function
func auth(r *http.Request) error {
	_, err := username(r)
	return err
}

// helper function to check user credentials for POST requests
func getUserCredentials(r *http.Request) (*credentials.Credentials, error) {
	var msg string
	// user didn't use web interface, we switch to POST form
	//     name := r.FormValue("name")
	ticket := r.FormValue("ticket")
	fname := fmt.Sprintf("krb-%d", time.Now().UnixNano())
	tmpFile, err := ioutil.TempFile("/tmp", fname)
	if err != nil {
		msg = fmt.Sprintf("Unable to create tempfile: %v", err)
		log.Printf("ERROR: %s", msg)
		return nil, errors.New(msg)
	}
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.Write([]byte(ticket))
	if err != nil {
		msg = "unable to write kerberos ticket"
		log.Printf("ERROR: %s", msg)
		return nil, errors.New(msg)
	}
	err = tmpFile.Close()
	creds, err := kuserFromCache(tmpFile.Name())
	if err != nil {
		msg = "wrong user credentials"
		log.Printf("ERROR: %s", msg)
		return nil, errors.New(msg)
	}
	if creds == nil {
		msg = "unable to obtain user credentials"
		log.Printf("ERROR: %s", msg)
		return nil, errors.New(msg)
	}
	return creds, nil
}

*/

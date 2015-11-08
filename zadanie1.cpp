#include <openssl\aes.h>
#include <openssl\rand.h>
#include <openssl\evp.h>
#include <cstring>
#include <fstream>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <cstdlib>

using namespace std;
string odczytZPliku(char *location)
{
	char *buffer = NULL;
	long length;

	FILE *file = fopen(location, "rb");
	if (!file == NULL)
	{
		fseek(file, 0, SEEK_END);
		length = ftell(file);
		fseek(file, 0, SEEK_SET);
		buffer = (char *)malloc(length * sizeof(char));
		if (buffer)
		{
			fread(buffer, 1, length, file);
		}
		fclose(file);
		return string(buffer, length);
	}
	else
	{
		return "";
	}
}
void zapisDoPliku(string do_pliku, string gdzie)
{
	std::ofstream output1(gdzie, std::ios::trunc | std::ios::binary);
	output1 << do_pliku << endl;
	output1.close();
}

void generuj_klucze(string sciezka_do_keystore, int ile)
{
	for (int i = 1; i <= ile; i++)
	{
		unsigned char losowy_klucz[128];
		RAND_bytes(losowy_klucz, 128);
		ostringstream ss;
		ss << i;
		string str = ss.str();
		string sciezka = sciezka_do_keystore + "\\" + str + ".key";
		zapisDoPliku(reinterpret_cast<char*>(losowy_klucz), sciezka);
	}	
}

string pobierz_klucz(string sciezka_do_keystore, char * id)
{
	string sciezka = sciezka_do_keystore +"\\"+ id + ".key";
	string klucz = odczytZPliku((char *) sciezka.c_str());
	if (klucz != "")
	{
		return klucz;
	} 
	else
	{
		cout << "Nie znaleziono klucza o podanym ID"<<endl;
		return "";
	}
	
}


BOOL koduj(char *lokalizacja, string _password, string _klucz)
{
	string do_zakodowania = odczytZPliku(lokalizacja);
	if (_klucz == "" || do_zakodowania=="")
	{
		return false;
	}
	else
	{
		unsigned char *klucz = (unsigned char *)_klucz.c_str();
		unsigned char *password = (unsigned char*)_password.c_str();

		unsigned char *zakoduj = (unsigned char*)do_zakodowania.c_str();
		int outlen1, outlen2;
		unsigned char *zakodowane = new unsigned char[(do_zakodowania.length() + 1) * 2];

		EVP_CIPHER_CTX ctx;
		EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), klucz, password);
		EVP_EncryptUpdate(&ctx, zakodowane, &outlen1, zakoduj, (do_zakodowania.length() + 1));
		EVP_EncryptFinal(&ctx, zakodowane + outlen1, &outlen2);

		string to_file = string((char*)zakodowane, outlen1);
		string lokal = string(lokalizacja);
		zapisDoPliku(to_file, "zakodowany" + lokal.substr(lokal.find_last_of('.')));
		return true;
	}
}

BOOL odkoduj(char *lokalizacja, string _password, string _klucz)
{
	string do_odkodowania = odczytZPliku(lokalizacja);
	if (_klucz == "" || do_odkodowania == "")
	{
		return false;
	}
	else
	{
		unsigned char *klucz = (unsigned char *)_klucz.c_str();
		unsigned char *password = (unsigned char*)_password.c_str();

		unsigned char * zakodowane = (unsigned char *)do_odkodowania.c_str();		
		unsigned char *odkodowane = new unsigned char[(do_odkodowania.length() + 1) * 2];
		int outlen1, outlen2;

		EVP_CIPHER_CTX ctx;
		EVP_DecryptInit(&ctx, EVP_aes_128_cbc(), klucz, password);
		EVP_DecryptUpdate(&ctx, odkodowane, &outlen1, zakodowane, (do_odkodowania.length() + 1));
		EVP_DecryptFinal(&ctx, odkodowane + outlen1, &outlen2);

		string to_file = string((char*)odkodowane, outlen1);
		string lokal = string(lokalizacja);
		zapisDoPliku(to_file, "odkodowany" + lokal.substr(lokal.find_last_of('.')));
		return true;
	}

}

//Poprawa dzia³ania has³a
int main(int argc, char **argv)
{

	//Jeœli nie masz wygenerowanego keystore to sobie odkomentuj linijke ponizej:
	generuj_klucze("keystore", 20);


	if (argc != 4)
	{
		cout << "za malo parametrow";
		return 0;
	}

	string password;
	cout << "Wpisz haslo" << endl;
	cin >> password;
	
	if (string(argv[1]) == "szyfruj")
	{
		BOOL check = koduj(argv[2], password , pobierz_klucz("keystore", argv[3]));
		if (check)
		{
			cout << "zakodowano pomyslnie"<< endl;
		}
		else
		{
			cout << "nie udalo sie zakodowad pliku"<<endl;
		}
	}
	else if (string(argv[1]) == "deszyfruj")
	{
		BOOL check = odkoduj(argv[2], password, pobierz_klucz("keystore", argv[3]));
		
		if (check)
		{
			cout << "odkodowano pomyslnie"<<endl;
		}
		else
		{
			cout << "nie udalo sie odkodowac pliku"<<endl;
		}
	}
	
	
	


	return 0;
}
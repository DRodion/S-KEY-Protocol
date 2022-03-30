#include <iostream>
#include <map>
#include <string> 
#include <vector>

//����� ��� ����������� ���������� Crypto++
#include "../cryptopp860/cryptlib.h"
#include "../cryptopp860/des.h" // DES algorithm
#include "../cryptopp860/modes.h"
#include "../cryptopp860/filters.h"
#include "../cryptopp860/osrng.h" // PNG AutoSeededX917RNG
#include "../cryptopp860/sha.h"
#include "../cryptopp860/base64.h"


using namespace CryptoPP;
using namespace std;

//���������� ��������
const int COUNT_ROUND = 5;
//������ ���������� ����� N � ������
const unsigned int BLOCKSIZE = 64;

////������� ����������� sha256 � ������� base64
string SHA256HashString(string aString) {
    string digest;
    SHA256 hash;

    StringSource foo(aString, true, new HashFilter(hash, new Base64Encoder(new StringSink(digest))));

    return digest;
}


class Server {
private:
    // ��������� ��� �������� ������ ���� [���� � ��������]
    map <string, vector <string>> db; //�������� ��������������� ������������������ �� �������
    map <string, string> db_N; //�������� ��������������� ����� N
    map <string, int> db_I; // ����� ����������
    map <string, string> db_last_pass; // ��������� �������� ��������������� ������
    unsigned char N; // ����� N

public:
    // ������� ��������� ������ ����������
    int generator_I(string login) {
        cout << "Server: User ����������� ��������������... �����: '" << login << "'" << endl;
        const auto found_N2 = db.find(login);
        if (found_N2 != db.cend()) {
            return db_I[login];
        }
        else {
            cout << "Server: ������ � ��������� ���������� I. ������������ �����. " << endl;
            return 0;
        }
    }
    // ������� ��������� ���������� ����� N � ������� ���������������� �������� ����������
    string generator_N() {
        string hash_N;
        byte* pcbScratch;
        pcbScratch = new byte[BLOCKSIZE];
        // �������� ���������������� �������� ����������
        AutoSeededX917RNG<DES_EDE3> rng;
        string N_str;

        cout << "User: ��������� ����� N..." << endl;
        rng.GenerateBlock(pcbScratch, BLOCKSIZE); //��������� ���������� �����

        for (int i = 0; i < BLOCKSIZE; i++) {
             N_str += pcbScratch[i];
        }
        cout << "User: ��������� ������ �������. N = " << SHA256HashString(N_str) << endl;
        return N_str;

        delete[] pcbScratch;
    }
    //������� ��������� ������������������ �� �������
    vector<string> generator_password(unsigned char k) {
        string new_pass, hash_pass;
        vector<string> password; // ������ ��� �������� ������������������ �� �������

        new_pass = k + N;
        for (int i = 0; i < COUNT_ROUND; i++) {
            hash_pass = SHA256HashString(new_pass);
            password.push_back(hash_pass);
            new_pass = hash_pass;
        }
        return password;
    }
    //������� �����������
    int registration(string login, unsigned char k) {
        const auto found = db.find(login);
        string new_N;
        if (found == db.cend()) {
            db_I[login] = 1;
            new_N = generator_N();
            cout << "Server: �����������..." << endl;

            db[login] = generator_password(k);

            cout << "Server: ��������� ������..." << endl;
            db_last_pass[login] = db[login][COUNT_ROUND - 1];

            cout << "Server: ����������� ������ �������. ������ � ���� db: " << endl;
            //����� ���������� �� �������� ���������������� ������������������� �� �������
            for (const auto& el : db) {
                cout << el.first << " -> [" << endl;
                for (const auto& s : el.second) {
                    cout << s << (&s == &el.second.back() ? "]" : "");
                }
                cout << endl;
            }
            return true;
        }
        else {
            cout << "Server: Error. ������������ ��� ��������������� � ����� �������." << endl;
            return false;
        }
    }
    //������� �����������
    void auth(string login, string password) {
        cout << "Server: �������� ������..." << endl;
        if (SHA256HashString(password) == db_last_pass[login]) {
            cout<< "Server: ��������� ���������� �������!" << endl;
            cout << "Server: ������, ���������� �� �������: " << db_last_pass[login] << endl;
            cout << "Server: ������, ������� ������� User: " << SHA256HashString(password) << endl;
            db_I[login] += 1;
            db_last_pass[login] = password;

            cout << "Server: �������� ��������������." << endl;
        }
        else {
            cout << "Server: ������������ ������." << endl;
        }
    }
};

//����� ������������
class User
{
private:
    // ��������� ��� �������� ������ ���� [���� � ��������]
    vector<string> db_password;
    unsigned char N;
public:
    //������� ��������� ������������������ �� �������
    vector<string> generator_password(unsigned char k) {
        string new_pass, hash_pass;
        vector<string> password;

        new_pass = k + N;
        for (int i = 0; i < COUNT_ROUND; i++) {
            hash_pass = SHA256HashString(new_pass);
            password.push_back(hash_pass);
            new_pass = hash_pass;
        }
        return password;
    }
    //������� �����������
    void registration_user(Server& server, string login, unsigned char key) {
        server.registration(login, key); //����� ������� ����������� �� �������
        db_password = generator_password(key); //��������� ������������������ �� �������
    }
    //������� ����������� ������������
    void auth_user(Server& server, string login) {
        int transaction;
        string pass_I;

        cout << "User: ������ �� ��������������. ��������� ���������� I ��������... "<< endl;
        transaction = server.generator_I(login); //����� ������� ��������� ������ ���������� �� �������
        if (transaction != 0) {
            cout << "User: ����� ���������� I: " << transaction << endl;
            pass_I = db_password[COUNT_ROUND - transaction - 1];
            server.auth(login, pass_I); //����� ������� �������������� �� �������
            cout << "User: ������������������� ������������. " << endl;
            cout << endl;
        }
        else {
            cout << "User: ������ ��� ��������������" << endl;
        }

    }
};

int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "rus");

    //��������� ����
    byte key{0b11010111};

    Server objSKEYServer; // ���������� Server
    User objSKEYUser; // ���������� User

    // ���������� ������
    /*objSKEYUser.registration_user(objSKEYServer, "Boby", key);

    for (int p = 0; p < COUNT_ROUND - 1; p++) {
        objSKEYUser.auth_user(objSKEYServer, "Boby");
    }*/

    //������������ ������
    //objSKEYUser.regisration_user(objSKEYServer, "Alice", "123");
    //objSKEYUser.auth_user(objSKEYServer, "Alice", "qr1258963");
    
    objSKEYUser.registration_user(objSKEYServer, "Boby", key);

    for (int p = 0; p < COUNT_ROUND - 1; p++) {
        objSKEYUser.auth_user(objSKEYServer, "Alice");
    }


    system("pause");
    return 0;
}

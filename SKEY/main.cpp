#include <iostream>
#include <map>
#include <string> 
#include <vector>

//файлы для подключения библиотеки Crypto++
#include "../cryptopp860/cryptlib.h"
#include "../cryptopp860/des.h" // DES algorithm
#include "../cryptopp860/modes.h"
#include "../cryptopp860/filters.h"
#include "../cryptopp860/osrng.h" // PNG AutoSeededX917RNG
#include "../cryptopp860/sha.h"
#include "../cryptopp860/base64.h"


using namespace CryptoPP;
using namespace std;

//количество итераций
const int COUNT_ROUND = 5;
//размер случайного числа N в байтах
const unsigned int BLOCKSIZE = 64;

////функция хеширования sha256 с выводом base64
string SHA256HashString(string aString) {
    string digest;
    SHA256 hash;

    StringSource foo(aString, true, new HashFilter(hash, new Base64Encoder(new StringSink(digest))));

    return digest;
}


class Server {
private:
    // контейнер для хранения данных вида [ключ — значение]
    map <string, vector <string>> db; //случайно сгенерированная последовательность из паролей
    map <string, string> db_N; //случайно сгенерированное число N
    map <string, int> db_I; // номер транзакции
    map <string, string> db_last_pass; // последний случайно сгенерированный пароль
    unsigned char N; // число N

public:
    // функция генерации номера транзакции
    int generator_I(string login) {
        cout << "Server: User запрашивает аутентификацию... Логин: '" << login << "'" << endl;
        const auto found_N2 = db.find(login);
        if (found_N2 != db.cend()) {
            return db_I[login];
        }
        else {
            cout << "Server: Ошибка в генерации транзакции I. Неправильный логин. " << endl;
            return 0;
        }
    }
    // функция генерации случайного числа N с помощью криптографически стойкого генератора
    string generator_N() {
        string hash_N;
        byte* pcbScratch;
        pcbScratch = new byte[BLOCKSIZE];
        // Создание криптографически стойкого генератора
        AutoSeededX917RNG<DES_EDE3> rng;
        string N_str;

        cout << "User: Генерация числа N..." << endl;
        rng.GenerateBlock(pcbScratch, BLOCKSIZE); //генерация случайного числа

        for (int i = 0; i < BLOCKSIZE; i++) {
             N_str += pcbScratch[i];
        }
        cout << "User: Генерация прошла успешно. N = " << SHA256HashString(N_str) << endl;
        return N_str;

        delete[] pcbScratch;
    }
    //функция генерации последовательности из паролей
    vector<string> generator_password(unsigned char k) {
        string new_pass, hash_pass;
        vector<string> password; // вектор для хранения последовательности из паролей

        new_pass = k + N;
        for (int i = 0; i < COUNT_ROUND; i++) {
            hash_pass = SHA256HashString(new_pass);
            password.push_back(hash_pass);
            new_pass = hash_pass;
        }
        return password;
    }
    //функция регистрации
    int registration(string login, unsigned char k) {
        const auto found = db.find(login);
        string new_N;
        if (found == db.cend()) {
            db_I[login] = 1;
            new_N = generator_N();
            cout << "Server: Регистрация..." << endl;

            db[login] = generator_password(k);

            cout << "Server: Получение пароля..." << endl;
            db_last_pass[login] = db[login][COUNT_ROUND - 1];

            cout << "Server: Регистрация прошла успешно. Данные в базе db: " << endl;
            //вывод контейнера со случайно сгенерированными последовательностью из паролей
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
            cout << "Server: Error. Пользователь уже зарегистрирован с таким логином." << endl;
            return false;
        }
    }
    //функция авторизации
    void auth(string login, string password) {
        cout << "Server: Провекра пароля..." << endl;
        if (SHA256HashString(password) == db_last_pass[login]) {
            cout<< "Server: Произошло совпадение паролей!" << endl;
            cout << "Server: Пароль, хранящийся на сервере: " << db_last_pass[login] << endl;
            cout << "Server: Пароль, который передал User: " << SHA256HashString(password) << endl;
            db_I[login] += 1;
            db_last_pass[login] = password;

            cout << "Server: Успешная аутентификация." << endl;
        }
        else {
            cout << "Server: Неправильный пароль." << endl;
        }
    }
};

//Класс Пользователь
class User
{
private:
    // контейнер для хранения данных вида [ключ — значение]
    vector<string> db_password;
    unsigned char N;
public:
    //функция генерации последовательности из паролей
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
    //функция регистрации
    void registration_user(Server& server, string login, unsigned char key) {
        server.registration(login, key); //вызов функции регистрации на Сервере
        db_password = generator_password(key); //генерация последовательности из паролей
    }
    //функция авторизации пользователя
    void auth_user(Server& server, string login) {
        int transaction;
        string pass_I;

        cout << "User: Запрос на аутентификацию. Генерация транзакции I сервером... "<< endl;
        transaction = server.generator_I(login); //вызов функции генерации номера транзакции на Сервере
        if (transaction != 0) {
            cout << "User: Номер транзакции I: " << transaction << endl;
            pass_I = db_password[COUNT_ROUND - transaction - 1];
            server.auth(login, pass_I); //вызов функции аутентификации на Сервере
            cout << "User: Аутентифицированный пользователь. " << endl;
            cout << endl;
        }
        else {
            cout << "User: Ошибка при аутентификации" << endl;
        }

    }
};

int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "rus");

    //секретный ключ
    byte key{0b11010111};

    Server objSKEYServer; // объявление Server
    User objSKEYUser; // объявление User

    // Корректные данные
    /*objSKEYUser.registration_user(objSKEYServer, "Boby", key);

    for (int p = 0; p < COUNT_ROUND - 1; p++) {
        objSKEYUser.auth_user(objSKEYServer, "Boby");
    }*/

    //Некорректный пароль
    //objSKEYUser.regisration_user(objSKEYServer, "Alice", "123");
    //objSKEYUser.auth_user(objSKEYServer, "Alice", "qr1258963");
    
    objSKEYUser.registration_user(objSKEYServer, "Boby", key);

    for (int p = 0; p < COUNT_ROUND - 1; p++) {
        objSKEYUser.auth_user(objSKEYServer, "Alice");
    }


    system("pause");
    return 0;
}

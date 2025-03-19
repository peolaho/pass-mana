#include <iomanip>
#include <openssl/sha.h>
#include <sstream>
#include <iostream>
#include <random>
#include <fstream>
#include <string>
#include "SHA3_512.hpp"
#include "AES.hpp"
using namespace std;

const int PASSWORD_LENGTH = 32;

int main() {
  string pass_mana_password;
  cin >> pass_mana_password;
  pass_mana_password = sha3_512(sha3_512(pass_mana_password));

  string basic_pw_level;
  string pwmn_pass;
  ifstream basic_pw("passmana-data.pwc", ios_base::in);
  getline(basic_pw, basic_pw_level);
  getline(basic_pw, pwmn_pass);
  basic_pw.close();
  
  AES pass_encrypt(256);
  string decrypted_pass_cipherkey = pass_encrypt.decryption(basic_pw_level, pass_mana_password);
  if (pass_encrypt.encryption(sha3_512(pass_mana_password), sha3_512(decrypted_pass_cipherkey)) != pwmn_pass) {
    cout << "Wrong password!" << endl;
  };

  random_device rd;
  mt19937_64 gen(rd());
  uniform_int_distribution<long long int> dis(-9223372036854775807, 9223372036854775807);
  uniform_int_distribution<char> pw_dis(33, 127);
  
  ostringstream stream;
  for (int i = 0; i < 16; i++) {
    stream << setw(8) << setfill('0') << hex << dis(gen);
  }

  string cipher_key = stream.str();
  cipher_key = pass_encrypt.encryption(cipher_key, sha3_512(pass_mana_password + pass_encrypt.decryption(basic_pw_level, pass_mana_password)));
  cout << cipher_key << endl;

  string prog_name;
  cin >> prog_name;
  prog_name = pass_encrypt.encryption(prog_name, sha3_512(cipher_key + pass_mana_password));

  string pw = "";
  for (int i = 0; i < 32; i++) {
    pw += (char)(pw_dis(gen));
  }

  pw = pass_encrypt.encryption(pw, sha3_512(cipher_key + pass_mana_password));

  cout << pw        << endl;
  cout << prog_name << endl;

  ofstream pass_hashenc("pass-hash.pwc", ios_base::app);
  pass_hashenc << sha3_512(prog_name) << " " << sha3_512(pw) << " " << sha3_512(cipher_key) << "\n";
  pass_hashenc.close();

  ofstream pass_hash_table("pass-progw.pwc", ios_base::app);
  pass_hash_table << sha3_512(prog_name) << "|" << prog_name << "\n";
  pass_hash_table << sha3_512(pw)        << "|" << pw        << "\n";
  pass_hash_table.close();

  ofstream pass_cipherkey("pass-cipherkey.pwc", ios_base::app);
  pass_cipherkey << sha3_512(cipher_key)<< "|" << cipher_key<< "\n";
  pass_cipherkey.close();

  return 0;
}

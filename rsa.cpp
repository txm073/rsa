// C++ implementation of the RSA encryption algorithm
// Article guide here: 'https://www.geeksforgeeks.org/rsa-algorithm-cryptography/'

#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <ctime>
#include <random>
#include <string>
#include <utility>
#include <tuple>
#include <map>

using namespace std;

/* Utility functions */

// Get all prime numbers up to `n` as fast as possible
// Iterative implementation using the Sieve of Erotostines
vector<double> sieve(double n, vector<double> primes = {})
{
    vector<double> nums = {}, marker = {};
    for(double i = 2; i < n; ++i){
        nums.push_back(i);
        marker.push_back(0);
    }
    for(double index = 0; index < nums.size(); ++index){
        double number = nums[index];
        if(marker[index] == 0){
            primes.push_back(number);            
            for(double j = index + number; j < nums.size(); j += number){
                marker[j] = 1;
            }
        }
    }
    return primes;
}


// Check if an element exists in a provided vector
bool contains(double i, vector<double> vec)
{
    for(double j : vec){
        if(j == i){
            return true;
        }
    }
    return false;
}

// Check if a number is a prime according to a vector provided
// Returns true if the number `i` is not divisible by any elements in the vector
bool isPrime(double i, vector<double> primes)
{
    for(double j : primes){
        if(fmod(i, j) == 0){
            return false;
        }
    }
    return true;
}

// Return the highest common factor a.k.a greatest common divisor
double highestCommonFactor(double i, double j)
{
    double temp;
    while(true){
        temp = fmod(i, j);
        if(temp == 0){
            return j;
        }
        i = j;
        j = temp;
    }
}

// Check if two numbers are coprime
bool isCoprime(double i, double j)
{
    return highestCommonFactor(i, j) == 1;
}

// Calculate Eulers Totient function
// Returns the number relative primes (coprimes) to a number `n`
double totient(double n)
{   
    double coprimes = 0;
    for(int i = 1; i < n + 1; ++i){
        if(highestCommonFactor(i, n) == 1){
            coprimes++;
        }
    }
    return coprimes;
}

// Get a vector of all coprimes to a number `n`
vector<double> getCoprimes(double n)
{
    vector<double> coprimes;
    for(int i = 1; i < n + 1; ++i){
        if(highestCommonFactor(i, n) ==1){
            coprimes.push_back(i);
        }
    }
    return coprimes;
}

// Generate a pseudorandom integer within a certain range
double randint(double min, double max){
    double range = max - min + 1;
    double num = fmod(rand(), range) + min;
    return num;
}

// Convert a boolean value to a string (for printing)
string boolToString(bool b)
{
    return b ? "true" : "false";
}

// Write the pair of prime numbers to a text file in the form of strings
// Store the file as read-only and in a safe location since the prime pairs make up the private key
void writeToDisk(string fileName, double prime1, double prime2)
{
    string str1 = to_string((long long)prime1);
    string str2 = to_string((long long)prime2);
    string fileContents = str1 + "\n" + str2;
    ofstream file(fileName);
    file << fileContents;
    file.close();
}

/* Main implementation of the algorithm */

// Find a pair of large prime numbers 
// They can then be multiplied together to form the first part of the public key
vector<double> getLargePrimes(double lower, double upper, bool verbose = true)
{
    srand(static_cast<unsigned>(time(NULL)));
    vector<double> numsTried = {}, primesFound = {};
    vector<double> sqrtPrimes = sieve((double)sqrt(upper)); //multiSieve(lower, upper, maxVectorSize);
    if(verbose) cout << "Found " << sqrtPrimes.size() << " primes up to the square root of " << upper << endl;
    while(primesFound.size() != 2){
        double rand = randint(lower, upper);
        if(isPrime(rand, sqrtPrimes) && !contains(rand, numsTried)){
            primesFound.push_back(rand);
            if(verbose) cout << "Found a prime number between " << lower << " and " << upper << ": " << rand << endl;
        } 
        numsTried.push_back(rand);
        if(fmod(numsTried.size(), 1000) == 0 && verbose){
            cout << "Tried " << numsTried.size() << " random integers between " << lower << " and " << upper << endl;
        }
    }
    if(verbose) cout << "Found a pair of prime numbers after " << numsTried.size() << " generations" << endl;
    return primesFound;
}

double powMod(double d, double e, double mod)
{
    double original = d;
    for(int i = 0; i < e - 1; ++i){
        d = fmod(d * original, mod); 
    }
    return d;
}

vector<double> getCoefficients(double n, bool verbose = false)
{
    double totientOfN = totient(n);
    double e = getCoprimes(totientOfN)[1];
    double d = 1;
    while(true){
        int remainder = (int)fmod(e * d, totientOfN);
        if(verbose) cout << "Remainder: " << remainder << endl;
        if(remainder == 1){
            return vector<double>{d, e};
        }
        d++;
    }
}

vector<string> splitString(string str, string delim = " ")
{
    vector<string> splits = {};
    size_t pos_start = 0, pos_end, delim_len = delim.length();
    string token;
    while((pos_end = str.find(delim, pos_start)) != string::npos){
        token = str.substr(pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        splits.push_back(token);
    }
    splits.push_back(str.substr(pos_start));
    return splits;
}

void savePrivateKey(double privateKey, string fileName)
{
    ofstream file(fileName);
    file << to_string(privateKey);
    file.close();
}

double loadPrivateKey(string fileName)
{
    string d = "";
    ifstream file(fileName);
    getline(file, d);
    file.close();
    return stod(d);
}

void savePublicKey(vector<double> publicKey, string fileName)
{
    ofstream file(fileName);
    file << to_string(publicKey[0]) << "\n" << to_string(publicKey[1]);
    file.close();
}

vector<double> loadPublicKey(string fileName)
{
    string n = "", e = "";
    ifstream file(fileName);
    getline(file, n);
    getline(file, e);
    file.close();
    return vector<double>{stod(n), stod(e)};
}

pair<map<char, double>, map<double, char>> createCharmaps(vector<double> coprimes)
{
    string chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!'#$%&\"()*+,-./:;<=>?@[\\]^_`{|}~ ";
    map<char, double> charToInt = {};
    map<double, char> intToChar = {};
    for(int i = 1; i < chars.size() + 1; ++i){
        charToInt.insert({chars[i], coprimes[i]});
        intToChar.insert({coprimes[i], chars[i]});
    }
    return make_pair(charToInt, intToChar);
}

void saveCharmaps(map<char, double> charToInt, map<double, char> intToChar, string fileName)
{
    string writeString = "Character map:\n";
    for(const auto& [key, value] : intToChar){
        writeString += (to_string((int)key) + " : " + value + "\n");
    }
    ofstream file(fileName);
    file << writeString;
    file.close();
}

pair<map<char, double>, map<double, char>> loadCharmaps(string fileName)
{
    map<char, double> charToInt = {};
    map<double, char> intToChar = {};
    string contents = "";
    ifstream file(fileName);
    file >> contents;
    file.close();
    vector<string> lines = splitString(contents, "\n");
    lines.erase(lines.begin());
    for(string line : lines){
        vector<string> elements = splitString(line, " : ");    
        char character = *elements[1].c_str();
        double number = (double)atoi(elements[0].c_str());
        intToChar.insert({number, character});
        charToInt.insert({character, number});  
    }
    return make_pair(charToInt, intToChar);
}

string encode(vector<double> publicKey, string msg, map<char, double> charToInt)
{
    double n = publicKey[0], e = publicKey[1];
    string output = "";
    for(char character : msg){
        output += to_string((int)powMod(charToInt[character], publicKey[1], publicKey[0]));
        output += ":";    
    }
    return output.substr(0, output.length() - 1);
}

string decode(vector<double> publicKey, double privateKey, string msg, map<double, char> intToChar)
{
    string output = "";
    vector<string> splits = splitString(msg, ":");
    for(string numberString : splits){
        output += intToChar[powMod((double)atoi(numberString.c_str()), privateKey, publicKey[0])];
    }   
    return output;
}

void RSA(double lower, double upper, bool verbose = false, 
         string publicFile = "public.rsa", string privateFile = "private.rsa", 
         string charmapFile = "charmaps.rsa")
{
    vector<double> primes = getLargePrimes(1000, 5000);
    double p = primes[0], q = primes[1];
    //double p = 1000030897, q = 1000024523;
    double n = p * q;
    vector<double> coprimes = getCoprimes(n);
    vector<double> coefficients = getCoefficients(n);
    double d = coefficients[0], e = coefficients[1];
    if(verbose){
        cout << "Prime numbers (p): " << p << ", (q): " << q << endl;
        cout << "Product of primes (n): " << n << endl;
        cout << "Totient of n: " << coprimes.size() << endl;
        cout << "Private key (d): " << d << endl;
        cout << "Exponent (e): " << e << endl;
    }
    vector<double> publicKey = vector<double>{n, e};
    double privateKey = d; 
    pair<map<char, double>, map<double, char>> charmaps = createCharmaps(coprimes);
    map<char, double> charToInt = charmaps.first;
    map<double, char> intToChar = charmaps.second;
    saveCharmaps(charToInt, intToChar, charmapFile);
    savePublicKey(publicKey, publicFile);
    savePrivateKey(privateKey, privateFile);
}

int main(int argc, char* argv[])
{
    //RSA(1000, 5000, false);   
    vector<double> publicKey = loadPublicKey("public.rsa");
    cout << "Loaded public key: " << publicKey[0] << ", " << publicKey[1] << endl;
    double privateKey = loadPrivateKey("private.rsa");
    cout << "Loaded private key: " << privateKey << endl;
    pair<map<char, double>, map<double, char>> charmaps = loadCharmaps("charmaps.rsa");
    cout << "Loaded charmaps" << endl;
    map<char, double> charToInt = charmaps.first;
    map<double, char> intToChar = charmaps.second;

    string msg = "Hello World!";
    cout << powMod(powMod(69, publicKey[1], publicKey[0]), privateKey, publicKey[0]) << endl;

    cout << "Original message: " << "'" << msg << "'" << endl;
    //double encrypted = powMod(msg, e, n);
    string encrypted = encode(publicKey, msg, charToInt);
    cout << "Encrypted message: " << "'" << encrypted << "'" << endl;
    string decrypted = decode(publicKey, privateKey, encrypted, intToChar);
    cout << "Decrypted message: " << "'" << decrypted << "'" << endl;
    return 0;
}

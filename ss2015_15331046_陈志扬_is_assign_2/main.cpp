#include "MD5.cpp"
int main() {
	MD5 md;
	cout << "If you want to QUIT, please input the character '#'!" << endl;
	cout << "Please input the message that you want to encrypt:" << endl;
	string plain;
	cin >> plain;
	if (plain == "#") cout << "You have quit the program!" << endl;

	while (plain != "#") {
		cout << "The MD5 digest is:" << endl;
		cout << md.MD5_encrypt(plain) << endl;
		cout << "Congratulations! You have done it successfully." << endl << endl;

		cout << "Please input the message that you want to encrypt:" << endl;
		cin >> plain;
		if (plain == "#") cout << "You have quit the program!" << endl;
	}
	return 0;
}
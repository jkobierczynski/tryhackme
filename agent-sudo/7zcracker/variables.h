#include <windows.h>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <direct.h>
using namespace std;

LARGE_INTEGER begin, end, freq, begin1, end1, freq1;
int nr1 = 1;
ostringstream c1;
ostringstream var;
ostringstream ss;
ostringstream path;
ostringstream dpath;
string paths;
string Time_unit = " Seconds";
double Last_Time1;
double Last_Time2;
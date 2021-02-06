#include "variables.h"

bool directorytest()
{
   if( _mkdir( "\est" ) == 0 )
   {
      system( "dir \test" );
      if( _rmdir( "\est" ) == 0 )
	  {
		return true;
	  }
	  
   }
   return false;
}
int setupscreen ()
{

system("cls");
cout << "7z-Cracker		by	Justme2	V0.01	01/2010 \n";
ss.str("");
ss << "echo Cracking file: " << path.str().c_str() << " Trying: " << var.str().c_str() << "\n";
system(ss.str().c_str());
QueryPerformanceCounter(&end1);
Last_Time1 = (double)(end1.QuadPart  - begin1.QuadPart) / (double)freq1.QuadPart;
Last_Time2 = (60/Last_Time1)/60;
ss.str("");
ss << "echo Performance: " << Last_Time2 << " passwords/second\n";
system(ss.str().c_str());
QueryPerformanceCounter(&begin1);
return 0;
}
int main(int argc, char *argv[])
{
system("cls");
cout << "7z Cracker by Justme2 V0.01 01/2010 \n";
cout << "Enter Filename(Example: bla.7z):";
ss.str("");
cin >> paths;
cout << "Thank you. Now Cracking...\n";
path << paths;
if(QueryPerformanceFrequency(&freq) == 0)
{
     // not supported :-(
}
if(QueryPerformanceFrequency(&freq1) == 0)
{
     // not supported :-(
}
QueryPerformanceCounter(&begin);
QueryPerformanceCounter(&begin1);


for(nr1;nr1 < 99999999;nr1++)
{
c1 << nr1;
var << c1.str().c_str();
ss << "echo PW:" << var.str().c_str() << " >> log.log";
system(ss.str().c_str());
ss.str("");
ss << "7za.exe x -y -p" << var.str().c_str() <<" " << path.str().c_str() <<" -o\est -r";
system(ss.str().c_str());

if (directorytest()==false)
{
	QueryPerformanceCounter(&end);
	system("cls");
	ss.str("");
	ss << "echo The Password Was: '" << var.str().c_str() << "' >> log.log";
	system(ss.str().c_str());
	double Last_Time = (double)(end.QuadPart  - begin.QuadPart) / (double)freq.QuadPart;
	if(Last_Time > 60)
	{
		Last_Time = Last_Time / 60;
		Time_unit = " Minutes";
	}
	if(Last_Time > 60)
	{
		Last_Time = Last_Time / 60;
		Time_unit = " Hours";
	}
	if(Last_Time > 24)
	{
		Last_Time = Last_Time / 24;
		Time_unit = " Days";
	}
	ss.str("");
	ss << "echo Time Used: '" << Last_Time << "' Average Performance: '" << Last_Time2 <<"' Passwords/Minute >> log.log";
	system(ss.str().c_str());
	system("cls");
	cout << "7z-Cracker	by	Justme2 V0.01 01/2010 \n";
	ss.str("");
	ss << "echo The Password Was: '" << var.str().c_str() << "'";
	system(ss.str().c_str());
	ss.str("");
	ss << "echo Time Used: '" << Last_Time << "' "<< Time_unit << "' Average Performance: '" << Last_Time2 <<"' Passwords/Minute\n";
	system(ss.str().c_str());
	system("Pause");
	exit(1);
}

setupscreen();
var.str("");
c1.str("");
ss.str("");
}
return 0;
}
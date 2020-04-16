#include <iostream>
#include <fstream>
#include <chrono> //std::chrono
#include <ctime>  //ctime()
#include <string>

#include "CSV/CSV.hpp"
#include "Memory/Memory.h"

#define PATTERN_FILE "Patterns.txt"
#define DUMP_FILE "Offsets.hpp"

std::ofstream output;

enum InputFields
{
	FIELDS_TYPE,
	FIELDS_NAME,
	FIELDS_PATTERN,
	FIELDS_OFFSET,
	FIELDS_TYPESIZE
};

bool ParseFileToStruct(std::vector<PatternStruct> &vector)
{
	jay::util::CSVread csv_read(PATTERN_FILE,
		jay::util::CSVread::strict_mode
		| jay::util::CSVread::text_mode
		//jay::util::CSVread::process_empty_records
		//| jay::util::CSVread::skip_utf8_bom_check
	);

	if (csv_read.error)
	{
		std::cerr << PATTERN_FILE << " failed: " << csv_read.error_msg << std::endl;
		return false;
	}

	while (csv_read.ReadRecord())
	{
		PatternStruct ps = PatternStruct();

		for (unsigned i = 0; i < csv_read.fields.size(); ++i)
		{
			if (std::strcmp(csv_read.fields[FIELDS_TYPE].c_str(), "OFFSET") == 0)
				ps.type = TYPE_OFFSET;
			else if (std::strcmp(csv_read.fields[FIELDS_TYPE].c_str(), "ADDRESS") == 0)
				ps.type = TYPE_ADDRESS;
			else if (std::strcmp(csv_read.fields[FIELDS_TYPE].c_str(), "FUNCTION") == 0)
				ps.type = TYPE_ADDRESS_FUNCTION;
			else
				continue;

			if(csv_read.fields.size() > 4)
				ps.type_size = std::stoi(csv_read.fields[FIELDS_TYPESIZE]);
			else
				ps.type_size = 4; //4 is a DWORD

			ps.name = csv_read.fields[FIELDS_NAME];
			ps.pattern = csv_read.fields[FIELDS_PATTERN];
			ps.offset = std::stoi(csv_read.fields[FIELDS_OFFSET]);
		}

		if(ps.type != TYPE_INVALID)
			vector.push_back(ps);
	}

	if (csv_read.eof && (csv_read.record_num == csv_read.end_record_num))
	{
		return true;
	}

	return false;
}

void CreateDumpFile()
{
	//Create file
	output.open(DUMP_FILE);

	//Get Time Now
	auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	//Convert time to ctime format
	char str_time[MAXCHAR];
	ctime_s(str_time, MAXCHAR, &now);

	//write in file
	output << "#pragma once" << std::endl << std::endl;
	output << "/*" << std::endl;
	output << "Offset dumper by @Ph4nton" << std::endl;
	output << str_time;
	output << "*/" << std::endl << std::endl;
	output << "#define BASEADDRESS GetModuleHandle(NULL)" << std::endl;
}

int main(int argc, const char* argv[])
{
	CMemory Memory;
	std::vector<PatternStruct> pattern_struct;

	if (argc < 2) {
		std::cout << "Correct usage: " << argv[0] << " \"League of Legends.exe\"" << std::endl;
		system("pause");
		return 0;
	}

	if (!ParseFileToStruct(pattern_struct)) {
		system("pause");
		return 0;
	}

	if (!Memory.Initialize(argv[1])) {
		system("pause");
		return 0;
	}

	//Create output file
	CreateDumpFile();

	for (auto obj : pattern_struct)
	{
		//Get address from pattern
		auto address = Memory.Pattern(obj);

		//Save output in file
		output << "#define " << obj.name << " 0x" << std::hex << std::uppercase << address << "\t//" << obj.pattern << std::endl;

		//Print in console
		std::cout << obj.name << ": 0x" << std::hex << std::uppercase << address << std::endl;
	}

	//close file
	output.close();

	system("pause");

	return 0;
}
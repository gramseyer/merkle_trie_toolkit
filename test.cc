#include <catch2/catch_session.hpp>

#include <sodium.h>

int main(int argc, char** argv)
{
	if (sodium_init() == -1)
	{
		throw std::runtime_error("failed to init sodium");
	}
	int result = Catch::Session().run(argc, argv);
	return result;
}

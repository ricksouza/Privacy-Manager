################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../Cipher.cpp \
../Common.cpp \
../Encoder.cpp \
../SecretSharer.cpp \
../main.cpp 

CC_SRCS += \
../io.cc \
../lagrange.cc \
../polynomial.cc \
../systemparam.cc 

OBJS += \
./Cipher.o \
./Common.o \
./Encoder.o \
./SecretSharer.o \
./io.o \
./lagrange.o \
./main.o \
./polynomial.o \
./systemparam.o 

CC_DEPS += \
./io.d \
./lagrange.d \
./polynomial.d \
./systemparam.d 

CPP_DEPS += \
./Cipher.d \
./Common.d \
./Encoder.d \
./SecretSharer.d \
./main.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

%.o: ../%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '



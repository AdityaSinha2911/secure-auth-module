CXX      = g++
CXXFLAGS = -Wall -Wextra -O2 -std=c++17
LDFLAGS  = -lssl -lcrypto

# All source files including new modules
SRCS = main.cpp \
       security_logger.cpp \
       rbac.cpp \
       credential_store.cpp \
       mfa_totp.cpp \
       session_manager.cpp \
       auth_core.cpp \
       pam_simulation.cpp \
       admin_dashboard.cpp

OBJS   = $(SRCS:.cpp=.o)
TARGET = auth_module

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) audit.log users.db users.db.tmp

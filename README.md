# TCP capture file info extracting Project

Project Overview
The purpose of this project is to analyze the TCP protocol behavior by parsing a TCP trace file and computing detailed statistics
and state information for each TCP connection. The project will help you understand TCP state transitions, round-trip times (RTTs),
and data transmission statistics.

Requirements
The project involves writing a Python program to:

Parse a TCP .cap file.
Track and manage the state information for each TCP connection.
Compute and display summary information about TCP connections.

Features
tcp_unpack.py: It holds the main function and responsible for extracting the formal .cap file
tcp_management.py: It responsible for recording and managing all connections among the .cap file
tcp_connection.py: It responsible for managing the information of each single connection
packet_struct.py: It includes all the classes for supporting the oriented-programming extracting the .cap files
(the packet_struct.py file provided through the brightspace, and the professor allowed us to import and directly use it)


Input
A .cap file (e.g., sample-capture-file.cap) that includes packet data from multiple TCP connections.

Output
The program should output:

Detailed information for each TCP connection.
General statistics about the TCP connections in the trace.
Statistical data for complete TCP connections, including duration, RTT values, packet counts, and window sizes.

How to Use
Prerequisites:
Python 3.x installed on your system.
Ensure the packet module is available in your Python environment (it is included by default).

Running the Program
To execute the program on the Linux server linux.csc.uvic.ca, use the following command:
python3 tcp_unpack.py <inputfile>
for example:
python3 tcp_unpack.py sample-capture-file.cap
(The inputfile must be a formal .cap file, or the program would not accept it)

Important Note
The program should be run in an environment where only Python 3 and its standard libraries are available (as specified in the assignment).
Do not attempt to use any additional Python packages outside of those provided by default.




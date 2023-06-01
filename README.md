# SAMPARK
This is a partial implementation of the [paper](https://doi.org/10.1016/j.jisa.2022.103381) titled "SAMPARK: Secure and lightweight communication protocols for smart parking management".

The first step involves registration of the Vehicle User/Parking owner with the Trusted Authority(TA).

NOTE: All files need to be run from the directory in which they are present.

1. The first step is the System Initialization phase, run by the TA. Simply do 
` python3 TA_SysInitPhase.py `
2. The second step is for the TA to accept registrations of Vehicle Users. First run the TA file.

` python3 TA_RegPhase.py `

3. Next, for each Vehicle User registration, go to the Vehicle User directory, and run the VU_RegPhase.py file by providing an integer as a command line argument, which would be the number of the vehicle registering.
` python3 VU_RegPhase.py <INDEX of Vi> `

4. Go to the OBU directory, and run the OBU_RegPhase.py file, by providing an integer as a command line argument, which would be same as the number of the vehicle registering.

` python3 OBU_RegPhase.py <INDEX of Vi> `

5. From the output of running the VU_RegPhase.py file, copy the RCVi number and provide it as input to the TA_RegPhase.py file, which would be waiting for the same input.

6. Registration is done. For registering another vehicle user, repeat the steps from 3.
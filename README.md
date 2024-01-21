This is my solution for the code challange https://codingchallenges.substack.com/p/coding-challenge-45-port-scanner


Is not completed yet, but already solve the 5 point presents in the challenge


Some of the things that have to improve:
 - Calculate work thread for the maximum performance and reduce the time execution
 - Implement args CIDR notation for the full range ipv4/v6 scan ports


how to execute:
 - sudo env "PATH=$PATH" python src/main.py --host=74.207.244.221
 - python src/main.py --host=74.207.244.221 --port=22

chmod 700 mailtorkey.pem
scp -i mailtorkey.pem ubuntu@ec2-50-19-162-249.compute-1.amazonaws.com:/home/ubuntu/p2pstorage/bootstrap_contacts .

chmod 700 mailtorkey.pem
scp -i mailtorkey.pem ubuntu@ec2-50-17-89-139.compute-1.amazonaws.com:/home/ubuntu/p2pstorage/bootstrap_contacts .

I have rewritten the entropy code here ,as i used 4 hosts connected via 2 SDN switch to a controller,
there is an attacker and a victim .

1.There can be any number of hosts connected to their respective switches 
    and these switches share a common controller,now the attack is targeted on compromissing the controller.

2.Thus you have to understand that there can be any number of hosts and 
    switches but each switch communicates through a common port with the controller.

3.So our system should calculate the entropy using the packets that have been
    flowing out of each port in our network.

4.The advantage of calculating the packets from each port , 
    finding the attacker port and blocking that port will benifit us when 
    the attacker host is doing mac spoofing or ip spoofing or both.


    in my code variables b1 and b2 are the values in bytes of the packets sourcing out of data port id 1 
        and data port id 2.
Now the entropy formula is
                             
Equation  1 shows a window where Xi is the random variable ,and  Yi represent its frequency 
.To compute the entropy .
Equation 2 is used where P(xi) denotes the probability of occurrence of each random variable in the set 

			W={ (x1,y1),(x2,y2),(x3,y3).............(Xn,Yn)}

			P(xi)=yi/N

			N=y1+y2+y3+..............Yn

	Where N,represent the total number of occurance of all the outcomes .the entropy of a discrete random variable(X)
	that is present in a system is defined as 				
			     n
			E(x)=Σ -P(xi)(log base 2) P(x)
			     i=1



Here N is sum of b1 + b2 (b1 is port 1 byte value and b2 is port 2 byte value )

Now if you want to find entropy of b1 then you have to do  :
                                                            P(x1)=b1/N

                                                                  2
                                                            E(X1)=Σ-P(x1)(log base 2) P(x)
                                                                  i=1
Now if you want to find entropy of b2 then you have to do  :
                                                            p(x2)=b2/N
                                                            
                                                                  2
                                                            E(X2)=Σ-P(x2)(log base 2) P(x)
                                                                  i=1

    finaly you have to do:
                                  N           E(X)
                                 E (X)= -----------------
                                         log(base 2) * 2

so please rewrite the entropy part of the python code as above based solution.






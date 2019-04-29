```
Synopsis
This project contains the implementation details of the proposed scheme in "A Lightweight Anonymous Authentication Framework with Resilience of Asynchronization Attacks for Wireless Sensor Networks".

Environmental requirements
Programs can run under Windows, Linux, and Macs. 
Install Proverif 1.96, download Address: http://proverif.inria.fr/
No additional libraries are required. 
ProVerif is a command-line tool which can be executed using the syntax:
           ./proverif [options] filename

Code example，"IEN-lightweight.pv" is the filename



./proverif.exe IEN-lightweight.pv


Process:
{1}new Kui: key;
{2}new Ksi: key;
{3}new PID: bitstring;
{4}let PIDnew: bitstring = PID in
{5}let PIDold: bitstring = Null in
{6}let Kui_48: key = Ksi in
(
    {7}!
    {8}out(c, (PID,senc(Data1,Kui_48)));
    {9}event acceptsUser(PID);
    {10}in(c, x_49: bitstring);
    {11}let m_50: bitstring = sdec(x_49,Kui_48) in
    {12}let PID_51: bitstring = Split1(m_50) in
    {13}let da2: bitstring = Split2(m_50) in
    {14}if (da2 = Data2) then
    {15}let Kui_52: key = h(Kui_48) in
    {16}out(c, senc(res,Kui_52));
    {17}event termUser(PID_51)
) | (
    {18}!
    {19}in(c, (Pi: bitstring,ct: bitstring));
    {20}event acceptsGWN(PIDold);
    {21}if (PIDnew = Pi) then
    {22}new Pnew: bitstring;
    {23}let PIDnew_53: bitstring = Pnew in
    {24}if (PIDnew_53 = Pi) then
    {25}if (PIDnew <> Null) then
    {26}let Ksi_54: key = h(Ksi) in
    {27}if (Data1 = sdec(ct,Ksi_54)) then
    {28}new Pnew_55: bitstring;
    {29}let PIDnew_56: bitstring = Pnew_55 in
    {30}let PIDold_57: bitstring = Pi in
    {31}out(c, senc(Concat(PIDnew_56,Data2),Ksi_54));
    {32}in(c, ct2: bitstring);
    {33}if (res = sdec(ct2,Ksi_54)) then
    {34}let Ksi_58: key = h(Ksi_54) in
    {35}let PIDold_59: bitstring = Null in
    {36}event termGWN(PIDold_59)
)

-- Query inj-event(termGWN(x_60)) ==> inj-event(acceptsUser(x_60))
Completing...
Starting query inj-event(termGWN(x_60)) ==> inj-event(acceptsUser(x_60))
RESULT inj-event(termGWN(x_60)) ==> inj-event(acceptsUser(x_60)) is true.
-- Query event(termUser(x_276)) ==> event(acceptsGWN(x_276))
Completing...
Starting query event(termUser(x_276)) ==> event(acceptsGWN(x_276))
RESULT event(termUser(x_276)) ==> event(acceptsGWN(x_276)) is true.
-- Query not attacker(Data2[])
Completing...
Starting query not attacker(Data2[])
RESULT not attacker(Data2[]) is true.
-- Query not attacker(Data1[])
Completing...
Starting query not attacker(Data1[])
RESULT not attacker(Data1[]) is true.
```

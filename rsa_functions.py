import binascii
import primes
import random
import mod_math
import timeit

def rsa_gen_keys(test_run=False, bits=1024, e=65537):
    if test_run:
        if bits == 1024:
            p = 150159479966345293925721454261213251088869815778430951479129372170907011086153443838752770349233708174961660860297212698028097207865689594273268671570054552340572156474025642297466584403151717541890149585228492196488230227470687079276681836034551238090972519586557098159601462842282927926104036027330160650639
            q = 164413796657208684782385753448661619052414628159491876180638032751074833011980007328437609661959175584218181859809286222851826040577307100639072744985880224292082626606626978962132821528578131434028390575986685056356453850291541187323855534880934641953551321501819586522270445191819399668448517121248181374431
        if bits == 4096:
            p = 715855317469299697193447641262393632276505283229177561219010290325029651111812721944822311090800345979292763266946283078527532438649324873407656197048595360989279298399415771527417549494048647521208259687952138850013141376443160343989452568427561162200919978845834384140981790787805066467948934378134701289944500094860934361621959708767375295209732428682377044442623792110566621819603256026835035256398125070044427845687660916193615206841768987013701263778450698630893970117650136458025412166974383063780284162675329670324678678050520949280253187433907154579700556492225852198512684400975887733569069554401766014438653051058830425064459435199144822204163198445213957081013720606786114916044506026040688938201175853580114059771164057355871885369114618599677445465254865270715844056536907414780849558818528758502317592145159458979718086373032158410635211129354257555603254473353086820297528491851752611625672945802404987283652419091289945279620340613576981414415752234893271384087929271405437448313997991036012649427119237633020870573547227898580742086754988845482850103320197905865516514195659786265272611694021146934897644609719017978405733091185229106495210807583834267641292355454463822222213488145163822786005047313640779403666681
            q = 955858034327238109861777833865577727680495224440177066201710622567557042241800903645451669265753649366027957569095699836093537982004130082400542868860445042462370757132324686591227804681568192558202976685868228467559238659286088298296505746406101406841149974822153166776746490970955973838342260995283905829414134777795907909410894918390791105242819932513961121316253298805419602948482954485658052631218616689808133940414579345626448758245210798588170889364102422189054582479598732583272801120792315438451929413465929538800144900387667653661188661574303265102296434744741045274892175812692119305356444672083210419472452005657797485132074917117461764607294677625315435543520775710846572250145716145646215931481565183220428651590630870353989949176634237549024810397858688057892402795509293137821857636180864700447907416155241226844776614993433689052831415316450392228854195891922344324664738575081467527139813733563361857497594316521087391137781092058991135737121628936760328172814359552834575377004544078876307891381248366941727593187987840652485382006138370337251365285527379532521037081868451005230063813967849738402321477685509517420494697120514487505178229915267099807384143826036075603720906885452090868395489316012705717632907479
    else:
        p = primes.generate_prime_number(bits)
        q = primes.generate_prime_number(bits)
    n = p*q
    lcm = mod_math.lcm( p-1, q-1 ) # Carmichael's totient
    d = mod_math.modinv(e, lcm)
    pk = (n, e)
    sk = (n, d)
    return (pk, sk, p, q)

def bitwise_square_multiply(M, d, N):
    C = 1
    z = M
    # As we shift, b will be consumed
    while d != 0:
        #print(i)
        # Check LSB
        if (d & 1) == 1:
            # Multiply
            C = (C * z) % N
        # Square
        z = (z * z) % N
        # Shift right by 1 bit
        d >>= 1
    return C

def bitwise_square_multiply_timings(M, d, N):
    totalt = timeit.default_timer()
    modt = 0
    modt_list = []
    C = 1
    z = M
    # As we shift, b will be consumed
    while d != 0:
        #print(i)
        # Check LSB
        if (d & 1) == 1:
            modt = timeit.default_timer()
            # Multiply
            C = (C * z) % N
            modt = timeit.default_timer() - modt
        # Square
        z = (z * z) % N
        # Shift right by 1 bit
        d >>= 1
        modt_list.append(modt)
    return C, totalt, modt_list

# Normal CRT Exponentiation
def comp_crt_exp( cs, ds, ns ):
    p = 0
    q = 1
    cp = bitwise_square_multiply(cs[p], ds[p], ns[p])
    cq = bitwise_square_multiply(cs[q], ds[q], ns[q])
    return (cp, cq)

# Chinese Remainder Theorem modular exponentiation
# c^d mod pq
def crt_exp(c, d, p, q, exp=comp_crt_exp):
    n = p*q
    # Map c part of Zn to Zp * Zq
    (cp, cq) = map_to_zpzq(c, p, q)
    # Calculate dp, dq
    # p, q are prime. Can use Fermat's little theorem
    ds = d % (p - 1), d % (q - 1)
    # Compute exponent on cp, cq seperately
    (cp, cq) = exp( (cp,cq), ds, (p,q) )
    # Map result back to Zn
    m = map_to_zn(p, q, cp, cq)
    return m

# Chinese Remainder Theorem modular exponentiation
# Implementing methods used in common RSA libraries
# https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm
# This should be faster
def crt_exp_prebaked(c, p, q, dp, dq, qinv):
    cp = bitwise_square_multiply(c, dp, p)
    cq = bitwise_square_multiply(c, dq, q)
    h = (qinv  * (cp - cq)) % p
    m = cq + (h * q)
    return m

# Convert a utf-8 string to int
def string_to_int(string):
    i = string.encode('utf8')
    i = binascii.hexlify(i)
    i = int(i, 16)
    return i

# Convert an int to utf-8
def int_to_string(num):
    i = hex(num)
    i = i[2:]
    i = i.encode('ascii')
    i = binascii.unhexlify(i)
    i = i.decode('utf-8')
    return i

# Map value a in group Zn isomorphic to Zp and Zq
def map_to_zpzq(a, p, q):
    return (a % p, a % q)

# Map values p, q in groups Zp, Zq isomorphic to Zn to group Zn
def map_to_zn(p, q, a, b):
    # Given group Zp * Zq = Zn,
    # we must find the inverse of p in Zq and the inverse of q in Zp
    # pinv is the number s.t. pinv*p === 1 mod q, pinv*p === 0 mod p
    # qinv is the number s.t. qinv*q === 1 mod q, qinv*q === 0 mod q
    pinv = mod_math.modinv(p, q)
    qinv = mod_math.modinv(q, p)

    # let s = pinv, t = pinv
    s = pinv
    t = qinv

    # if sp === 1 mod q, then a(sp) === a mod q
    # if tq === 1 mod p, then b(tq) === b mod p
    # To map from (Zp, Zq) -> Zn, we combine then mod p*q:
    mp = s*p*b
    mq = t*q*a
    return( (mp + mq) % (p * q) )


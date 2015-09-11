"""
link.py: interface and link abstractions for mininet

It seems useful to bundle functionality for interfaces into a single
class.

Also it seems useful to enable the possibility of multiple flavors of
links, including:

- simple veth pairs
- tunneled links
- patchable links (which can be disconnected and reconnected via a patchbay)
- link simulators (e.g. wireless)

Basic division of labor:

  Nodes: know how to execute commands
  Intfs: know how to configure themselves
  Links: know how to connect nodes together

Intf: basic interface object that can configure itself
TCIntf: interface with bandwidth limiting and delay via tc

Link: basic link class for creating veth pairs
"""

from mininet.log import info, error, debug
from mininet.util import makeIntfPair
import mininet.node
import re
import itertools

class Intf( object ):

    "Basic interface object that can configure itself."

    def __init__( self, name, node=None, port=None, link=None,
                  mac=None, **params ):
        """name: interface name (e.g. h1-eth0)
           node: owning node (where this intf most likely lives)
           link: parent link if we're part of a link
           other arguments are passed to config()"""
        self.node = node
        self.name = name
        self.link = link
        self.mac = mac
        self.ip, self.prefixLen = None, None

        # if interface is lo, we know the ip is 127.0.0.1.
        # This saves an ifconfig command per node
        if self.name == 'lo':
            self.ip = '127.0.0.1'
        # Add to node (and move ourselves if necessary )
        moveIntfFn = params.pop( 'moveIntfFn', None )
        if moveIntfFn:
            node.addIntf( self, port=port, moveIntfFn=moveIntfFn )
        else:
            node.addIntf( self, port=port )
        # Save params for future reference
        self.params = params
        self.config( **params )

    def cmd( self, *args, **kwargs ):
        "Run a command in our owning node"
        return self.node.cmd( *args, **kwargs )

    def ifconfig( self, *args ):
        "Configure ourselves using ifconfig"
        return self.cmd( 'ifconfig', self.name, *args )

    def setIP( self, ipstr, prefixLen=None ):
        """Set our IP address"""
        # This is a sign that we should perhaps rethink our prefix
        # mechanism and/or the way we specify IP addresses
        if '/' in ipstr:
            self.ip, self.prefixLen = ipstr.split( '/' )
            return self.ifconfig( ipstr, 'up' )
        else:
            if prefixLen is None:
                raise Exception( 'No prefix length set for IP address %s'
                                 % ( ipstr, ) )
            self.ip, self.prefixLen = ipstr, prefixLen
            return self.ifconfig( '%s/%s' % ( ipstr, prefixLen ) )

    def setMAC( self, macstr ):
        """Set the MAC address for an interface.
           macstr: MAC address as string"""
        self.mac = macstr
        return ( self.ifconfig( 'down' ) +
                 self.ifconfig( 'hw', 'ether', macstr ) +
                 self.ifconfig( 'up' ) )

    _ipMatchRegex = re.compile( r'\d+\.\d+\.\d+\.\d+' )
    _macMatchRegex = re.compile( r'..:..:..:..:..:..' )

    def updateIP( self ):
        "Return updated IP address based on ifconfig"
        # use pexec instead of node.cmd so that we dont read
        # backgrounded output from the cli.
        ifconfig, _err, _exitCode = self.node.pexec(
            'ifconfig %s' % self.name )
        ips = self._ipMatchRegex.findall( ifconfig )
        self.ip = ips[ 0 ] if ips else None
        return self.ip

    def updateMAC( self ):
        "Return updated MAC address based on ifconfig"
        ifconfig = self.ifconfig()
        macs = self._macMatchRegex.findall( ifconfig )
        self.mac = macs[ 0 ] if macs else None
        return self.mac

    # Instead of updating ip and mac separately,
    # use one ifconfig call to do it simultaneously.
    # This saves an ifconfig command, which improves performance.

    def updateAddr( self ):
        "Return IP address and MAC address based on ifconfig."
        ifconfig = self.ifconfig()
        ips = self._ipMatchRegex.findall( ifconfig )
        macs = self._macMatchRegex.findall( ifconfig )
        self.ip = ips[ 0 ] if ips else None
        self.mac = macs[ 0 ] if macs else None
        return self.ip, self.mac

    def IP( self ):
        "Return IP address"
        return self.ip

    def MAC( self ):
        "Return MAC address"
        return self.mac

    def isUp( self, setUp=False ):
        "Return whether interface is up"
        if setUp:
            cmdOutput = self.ifconfig( 'up' )
            # no output indicates success
            if cmdOutput:
                error( "Error setting %s up: %s " % ( self.name, cmdOutput ) )
                return False
            else:
                return True
        else:
            return "UP" in self.ifconfig()

    def rename( self, newname ):
        "Rename interface"
        self.ifconfig( 'down' )
        result = self.cmd( 'ip link set', self.name, 'name', newname )
        self.name = newname
        self.ifconfig( 'up' )
        return result

    # The reason why we configure things in this way is so
    # That the parameters can be listed and documented in
    # the config method.
    # Dealing with subclasses and superclasses is slightly
    # annoying, but at least the information is there!

    def setParam( self, results, method, **param ):
        """Internal method: configure a *single* parameter
           results: dict of results to update
           method: config method name
           param: arg=value (ignore if value=None)
           value may also be list or dict"""
        name, value = param.items()[ 0 ]
        f = getattr( self, method, None )
        if not f or value is None:
            return
        if isinstance( value, list ):
            result = f( *value )
        elif isinstance( value, dict ):
            result = f( **value )
        else:
            result = f( value )
        results[ name ] = result
        return result

    def config( self, mac=None, ip=None, ifconfig=None,
                up=True, **_params ):
        """Configure Node according to (optional) parameters:
           mac: MAC address
           ip: IP address
           ifconfig: arbitrary interface configuration
           Subclasses should override this method and call
           the parent class's config(**params)"""
        # If we were overriding this method, we would call
        # the superclass config method here as follows:
        # r = Parent.config( **params )
        r = {}
        self.setParam( r, 'setMAC', mac=mac )
        self.setParam( r, 'setIP', ip=ip )
        self.setParam( r, 'isUp', up=up )
        self.setParam( r, 'ifconfig', ifconfig=ifconfig )
        return r

    def delete( self ):
        "Delete interface"
        self.cmd( 'ip link del ' + self.name )
        # We used to do this, but it slows us down:
        # if self.node.inNamespace:
        # Link may have been dumped into root NS
        # quietRun( 'ip link del ' + self.name )

    def status( self ):
        "Return intf status as a string"
        links, _err, _result = self.node.pexec( 'ip link show' )
        if self.name in links:
            return "OK"
        else:
            return "MISSING"

    def __repr__( self ):
        return '<%s %s>' % ( self.__class__.__name__, self.name )

    def __str__( self ):
        return self.name


class TCHandle( object ):
    def __init__( self, handle ):
        self.handle = handle
        self.children = []

    def getCommands( self, *args, **kwargs):
        return []

    def addChild( self, child ):
        self.children.append(child)
        return child

    def childQdisc( self, *args,  **kwargs ):
        return self.addChild(TCQdisc(*args, parent=self.handle, **kwargs))

    def childClass( self, *args, **kwargs ):
        return self.addChild(TCClass(*args, parent=self.handle, **kwargs))

class TCRoot( TCHandle ):
    def __init__( self ):
        TCHandle.__init__(self, 'root')

    def isChangeableTo( self, other ):
        return isinstance(other, TCRoot)

    def needsChange( self, other ):
        assert self.isChangeableTo( other )
        return False

    def __repr__(self):
        return "TCRoot(children=%s)" % repr(self.children)

class TCQdisc( TCHandle ):
    def __init__( self, parent, qdisc, args, **params):
        TCHandle.__init__(self, **params)
        self.parent = parent
        self.qdisc = qdisc
        self.args = args

    def getCommands( self, tc, op, dev ):
        return ["{tc} qdisc {op} dev {dev} parent {parent} handle {handle} {qdisc} {args}".format(
            tc=tc, op=op, dev=dev, parent=self.parent,
            handle=self.handle, qdisc=self.qdisc, args=self.args
        )]

    def isChangeableTo( self, other ):
        if not isinstance(other, TCQdisc ):
            return False
        return (
            self.parent == other.parent and
            self.handle == other.handle and
            self.qdisc == other.qdisc
        )

    def needsChange( self, other ):
        assert self.isChangeableTo( other )
        return self.args != other.args

    def __repr__(self):
        return "TCQdisc(parent=%s, handle=%s, qdisc=%s, args=%s, children=%s)" % (
                repr(self.parent), repr(self.handle), repr(self.qdisc), repr(self.args), repr(self.children)
        )

class TCClass( TCHandle ):
    def __init__( self, parent, args, **params):
        TCHandle.__init__(self, **params)
        self.parent = parent
        self.args = args

    def getCommands( self, tc, op, dev ):
        return ["{tc} class {op} dev {dev} parent {parent} classid {handle} {args}".format(
            tc=tc, op=op, dev=dev, parent=self.parent, handle=self.handle,
            args=self.args
        )]
    
    def isChangeableTo( self, other ):
        if not isinstance(other, TCClass ):
            return False
        return (
            self.parent == other.parent and
            self.handle == other.handle
        )

    def needsChange( self, other ):
        assert self.isChangeableTo( other )
        return self.args != other.args
    
    def __repr__(self):
        return "TCClass(parent=%s, handle=%s, args=%s, children=%s)" % (
            repr(self.parent), repr(self.handle), repr(self.args), repr(self.children)
        )

class TCIntf( Intf ):
    """Interface customized by tc (traffic control) utility
       Allows specification of bandwidth limits (various methods)
       as well as delay, loss and max queue length"""

    # The parameters we use seem to work reasonably up to 1 Gb/sec
    # For higher data rates, we will probably need to change them.
    bwParamMax = 1000

    def __init__(self, *args, **kwargs):
        self.current_tc_root = None
        super(TCIntf, self).__init__(*args, **kwargs)

    @classmethod
    def limitBandwidth( cls, tc_node, bw=None, speedup=0, use_hfsc=False, use_tbf=False,
                latency_ms=None ):
        "Construct TC commands hierarchy for limiting bandwidth"

        if not bw:
            return tc_node

        if bw < 0 or bw > cls.bwParamMax:
            error( 'Bandwidth limit', bw, 'is outside supported range 0..%d'
                   % self.bwParamMax, '- ignoring\n' )
            return tc_node

        # FIXME: speedup arg needs some documentation and explanation
        # BL: this seems a bit brittle...
        if ( speedup > 0 and
             self.node.name[0:1] == 's' ):
            bw = speedup

        # This may not be correct - we should look more closely
        # at the semantics of burst (and cburst) to make sure we
        # are specifying the correct sizes. For now I have used
        # the same settings we had in the mininet-hifi code.
        if use_hfsc:
            tc_node = tc_node.childQdisc(
                            handle='5:', qdisc='hfsc', args='default 1'
                        )
            tc_node = tc_node.childClass(
                                handle='5:1',
                                args='hfsc sc rate %fMbit ul rate %fMbit' % ( bw, bw )
                            )
        elif use_tbf:
            # latency is the longest time packet can sit in TBF
            if latency_ms is None:
                # PP: what is this magic computation?
                # PP: is this correct if bw is integer?
                latency_ms = 15 * 8 / bw
            tc_node = tc_node.childQdisc(
                            handle='5:', qdisc='tbf', 
                            args='rate %fMbit burst 15000 latency %fms' % ( bw, latency_ms )
                        )
        else:
            tc_node = tc_node.childQdisc(
                            handle='5:', qdisc='htb', args='default 1'
                        )
            tc_node = tc_node.childClass(
                            handle='5:1', 
                            args='htb rate %fMbit burst 15k' % bw
                        )
        return tc_node

    @staticmethod
    def addQueueManagement( tc_node, bw=None, enable_ecn=False, enable_red=False ):
        # ECN or RED
        if enable_ecn or enable_red:
            tc_node = tc_node.childQdisc(
                            handle='6:',
                            qdisc='red',
                            args='limit 1000000 ' +
                                'min 30000 max 35000 avpkt 1500 ' +
                                'burst 20 ' +
                                'bandwidth %fmbit probability 1' % bw +
                                (' ecn' if enable_ecn else '')
                        )
        return tc_node

    @staticmethod
    def addDelay( tc_node, delay=None, jitter=None,
                   loss=None, max_queue_size=None ):
        if delay and delay < 0:
            error( 'Negative delay', delay, '\n' )
            return tc_node
        
        if jitter and jitter < 0:
            error( 'Negative jitter', jitter, '\n' )
            return tc_node

        if jitter and jitter > delay:
            error( 'Jitter', jitter, ' bigger than delay', delay, '\n' )
            return tc_node

        if loss and ( loss < 0 or loss > 100 ):
            error( 'Bad loss percentage', loss, '%%\n' )
            return tc_node

        # Delay/jitter/loss/max queue size
        netemargs = []
        if delay:
            netemargs.append( 'delay %sms' % delay )
        if jitter:
            netemargs.append( jitter )
        if loss:
            netemargs.append( 'loss %d' % loss )
        if max_queue_size:
            netemargs.append( 'limit %d' % max_queue_size )

        if netemargs:
            return tc_node.childQdisc( handle="10:", qdisc="netem", args=" ".join(netemargs) )
        else:
            return tc_node

    def getReconciliationSequence(self, old_node, new_node):
        debug("Reconciliate", old_node, " vs ", new_node, "\n")
        if old_node and new_node and old_node.isChangeableTo(new_node):
            if new_node.needsChange(old_node):
                yield ("change", new_node)
            for old, new in itertools.izip_longest(old_node.children, new_node.children):
                for tmp in self.getReconciliationSequence(old, new):
                    yield tmp
        else:
            # Okay, no change
            if old_node:
                yield ("remove", old_node)
                # Note: children are deleted automatically
            if new_node:
                yield ("add", new_node)
                for child in new_node.children:
                    for tmp in self.getReconciliationSequence(None, child):
                        yield tmp


    def config( self, bw=None, delay=None, jitter=None, loss=None,
                disable_gro=True, speedup=0, use_hfsc=False, use_tbf=False,
                latency_ms=None, enable_ecn=False, enable_red=False,
                max_queue_size=None, **params ):
        "Configure the port and set its properties."

        result = Intf.config( self, **params)

        # Disable GRO
        if disable_gro:
            self.cmd( 'ethtool -K %s gro off' % self )
        self.reconfig( bw=bw, delay=delay, jitter=jitter, loss=loss,
                       disable_gro=disable_gro, speedup=speedup, use_hfsc=use_hfsc,
                    use_tbf=use_tbf, latency_ms=latency_ms, enable_ecn=enable_ecn,
                    enable_red=enable_red)

    def reconfig( self, bw=None, delay=None, jitter=None, loss=None,
                disable_gro=True, speedup=0, use_hfsc=False, use_tbf=False,
                latency_ms=None, enable_ecn=False, enable_red=False,
                max_queue_size=None, **params ):
        debug(str(locals()))
        tc_root = TCRoot()
        tc_node = tc_root

        tc_node = self.limitBandwidth( tc_node, bw=bw, speedup=speedup,
                                       use_hfsc=use_hfsc, use_tbf=use_tbf,
                                       latency_ms=latency_ms )
        tc_node = self.addQueueManagement( tc_node, bw=bw,
                                           enable_ecn=enable_ecn,
                                           enable_red=enable_red )
        tc_node = self.addDelay( tc_node, delay=delay, jitter=jitter,
                                 loss=loss, max_queue_size=max_queue_size )

        tcoutputs = []
        if not self.current_tc_root:
            # Clear existing configuration
            tcoutputs.append(self.cmd('tc qdisc del dev %s root' % self.name))

        for op, node in self.getReconciliationSequence(self.current_tc_root, tc_root):
            cmds = node.getCommands( tc='tc', op=op, dev=self.name )
            for cmd in cmds:
                debug(" *** executing command: %s\n" % cmd)
                tcoutputs.append(self.cmd(cmd))

        self.current_tc_root = tc_root

        # Display configuration info
        stuff = []
        if bw is not None:
            stuff.append( '%.2fMbit' % bw )
        if delay is not None:
            stuff.append( '%s delay' % delay )
        if jitter is not None:
            stuff.append( '%s jitter' % jitter )
        if loss is not None:
            stuff.append( '%d%% loss' % loss )
        if enable_ecn:
            stuff.append( 'ECN' )
        if enable_red:
            stuff.append( 'RED' )
        info( '(' + ' '.join( stuff ) + ') ' )

        # Execute all the commands in our node
        for output in tcoutputs:
            if output != '':
                error( "*** Error: %s" % output )
        debug( "outputs:", tcoutputs, '\n' )
        #result[ 'tcoutputs'] = tcoutputs

        #return result


class Link( object ):

    """A basic link is just a veth pair.
       Other types of links could be tunnels, link emulators, etc.."""

    # pylint: disable=too-many-branches
    def __init__( self, node1, node2, port1=None, port2=None,
                  intfName1=None, intfName2=None, addr1=None, addr2=None,
                  intf=Intf, cls1=None, cls2=None, params1=None,
                  params2=None, fast=True ):
        """Create veth link to another node, making two new interfaces.
           node1: first node
           node2: second node
           port1: node1 port number (optional)
           port2: node2 port number (optional)
           intf: default interface class/constructor
           cls1, cls2: optional interface-specific constructors
           intfName1: node1 interface name (optional)
           intfName2: node2  interface name (optional)
           params1: parameters for interface 1
           params2: parameters for interface 2"""
        # This is a bit awkward; it seems that having everything in
        # params is more orthogonal, but being able to specify
        # in-line arguments is more convenient! So we support both.
        if params1 is None:
            params1 = {}
        if params2 is None:
            params2 = {}
        # Allow passing in params1=params2
        if params2 is params1:
            params2 = dict( params1 )
        if port1 is not None:
            params1[ 'port' ] = port1
        if port2 is not None:
            params2[ 'port' ] = port2
        if 'port' not in params1:
            params1[ 'port' ] = node1.newPort()
        if 'port' not in params2:
            params2[ 'port' ] = node2.newPort()
        if not intfName1:
            intfName1 = self.intfName( node1, params1[ 'port' ] )
        if not intfName2:
            intfName2 = self.intfName( node2, params2[ 'port' ] )

        self.fast = fast
        if fast:
            params1.setdefault( 'moveIntfFn', self._ignore )
            params2.setdefault( 'moveIntfFn', self._ignore )
            self.makeIntfPair( intfName1, intfName2, addr1, addr2,
                               node1, node2, deleteIntfs=False )
        else:
            self.makeIntfPair( intfName1, intfName2, addr1, addr2 )

        if not cls1:
            cls1 = intf
        if not cls2:
            cls2 = intf

        intf1 = cls1( name=intfName1, node=node1,
                      link=self, mac=addr1, **params1  )
        intf2 = cls2( name=intfName2, node=node2,
                      link=self, mac=addr2, **params2 )

        # All we are is dust in the wind, and our two interfaces
        self.intf1, self.intf2 = intf1, intf2
    # pylint: enable=too-many-branches

    @staticmethod
    def _ignore( *args, **kwargs ):
        "Ignore any arguments"
        pass

    def intfName( self, node, n ):
        "Construct a canonical interface name node-ethN for interface n."
        # Leave this as an instance method for now
        assert self
        return node.name + '-eth' + repr( n )

    @classmethod
    def makeIntfPair( cls, intfname1, intfname2, addr1=None, addr2=None,
                      node1=None, node2=None, deleteIntfs=True ):
        """Create pair of interfaces
           intfname1: name for interface 1
           intfname2: name for interface 2
           addr1: MAC address for interface 1 (optional)
           addr2: MAC address for interface 2 (optional)
           node1: home node for interface 1 (optional)
           node2: home node for interface 2 (optional)
           (override this method [and possibly delete()]
           to change link type)"""
        # Leave this as a class method for now
        assert cls
        return makeIntfPair( intfname1, intfname2, addr1, addr2, node1, node2,
                             deleteIntfs=deleteIntfs )

    def delete( self ):
        "Delete this link"
        self.intf1.delete()
        # We only need to delete one side, though this doesn't seem to
        # cost us much and might help subclasses.
        # self.intf2.delete()

    def stop( self ):
        "Override to stop and clean up link as needed"
        self.delete()

    def status( self ):
        "Return link status as a string"
        return "(%s %s)" % ( self.intf1.status(), self.intf2.status() )

    def __str__( self ):
        return '%s<->%s' % ( self.intf1, self.intf2 )


class OVSIntf( Intf ):
    "Patch interface on an OVSSwitch"

    def ifconfig( self, *args ):
        cmd = ' '.join( args )
        if cmd == 'up':
            # OVSIntf is always up
            return
        else:
            raise Exception( 'OVSIntf cannot do ifconfig ' + cmd )


class OVSLink( Link ):
    """Link that makes patch links between OVSSwitches
       Warning: in testing we have found that no more
       than ~64 OVS patch links should be used in row."""

    def __init__( self, node1, node2, **kwargs ):
        "See Link.__init__() for options"
        self.isPatchLink = False
        if ( isinstance( node1, mininet.node.OVSSwitch ) and
             isinstance( node2, mininet.node.OVSSwitch ) ):
            self.isPatchLink = True
            kwargs.update( cls1=OVSIntf, cls2=OVSIntf )
        Link.__init__( self, node1, node2, **kwargs )

    def makeIntfPair( self, *args, **kwargs ):
        "Usually delegated to OVSSwitch"
        if self.isPatchLink:
            return None, None
        else:
            return Link.makeIntfPair( *args, **kwargs )


class TCLink( Link ):
    "Link with symmetric TC interfaces configured via opts"
    def __init__( self, node1, node2, port1=None, port2=None,
                  intfName1=None, intfName2=None,
                  addr1=None, addr2=None, **params ):
        Link.__init__( self, node1, node2, port1=port1, port2=port2,
                       intfName1=intfName1, intfName2=intfName2,
                       cls1=TCIntf,
                       cls2=TCIntf,
                       addr1=addr1, addr2=addr2,
                       params1=params,
                       params2=params )

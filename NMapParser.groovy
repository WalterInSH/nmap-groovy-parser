import groovy.transform.ToString

public class NMapParser {

    public static final int DEFAULT_TIMEOUT = 30000

    static parse(String ip,int timeout){
        def sout = new StringBuilder(), serr = new StringBuilder()
        def proc = ('nmap -oX - ' + ip).execute() | 'grep port'.execute()
        proc.consumeProcessOutput(sout, serr)
        proc.waitForOrKill(timeout)

        def resultXml = sout.toString()
        if (resultXml == '') {
            return []
        }

        def resultList = []

        def rootNode = new XmlSlurper().parseText(resultXml)
        rootNode.port.each {
            def protocol = it.@protocol.toString()
            def port = Integer.parseInt(it.@portid.toString())
            def service = it.service[0].@name.toString()
            resultList << new ScanResult(port: port, protocol: protocol, service: service)
        }
        return resultList
    }

    static parse(String ip) {
        parse(ip, DEFAULT_TIMEOUT)
    }
}

@ToString(includeNames=true, includeFields=true)
class ScanResult{
    int port
    String protocol
    String service
}

package tool.java;

import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.*;

import soot.jimple.toolkits.callgraph.CallGraph;
import tool.consistency.ConsistencyAnalysis;
import tool.consistency.ConsistencyAnalysisResult;
import tool.java.preprocess;
import tool.ontology.EntityOntologyMap;
import tool.ontology.PrivacyOntologyMap;
import tool.modifyToTuple.*;
import tool.mapping.*;
import tool.analysis.infoflowResult;
import tool.other.*;

public class main {
    public static String apkPath = "E:\\\\tzy\\ContrastAPK\\test\\tv.periscope.android_v1.24.18.69-1900452_Android-4.4.apk";
    public static String jarsPath = "C:\\Program Files\\AndroidSDK\\platforms\\";
    public static String androidCallbackPath = "C:\\Users\\Administrator\\Desktop\\MyDroid\\configs\\FlowDroidConfigs\\AndroidCallBacks.txt";
    public static String sourceAndSinkPath = "C:\\Users\\Administrator\\Desktop\\MyDroid\\configs\\FlowDroidConfigs\\SourceAndSinks.txt";
    public static String easyTaintWrapperSource = "C:\\Users\\Administrator\\Desktop\\MyDroid\\configs\\FlowDroidConfigs\\EasyTaintWrapperSource.txt";

    //隐私策略的分析结果
    public static String privacyPolicyResults = "C:\\Users\\Administrator\\Desktop\\MyDroid\\configs\\policyResults.txt";

    //api方法和隐私信息的映射  apiMappingToPrivacy.txt
    public static String apiTOPrivacy = "C:\\Users\\Administrator\\Desktop\\MyDroid\\configs\\apiMappingToPrivacy.txt";
    //隐私信息本体  privacyOntology.txt
    public static String privacyTOOntology = "C:\\Users\\Administrator\\Desktop\\MyDroid\\configs\\privacyOntology.txt";
    //第三方实体的本体 entityOntology.txt
    public static String EntityOntology = "C:\\Users\\Administrator\\Desktop\\MyDroid\\configs\\entityOntology.txt";
    //ip地址到url的映射  ipMappingToDNS.txt
    public static String IPToDNS = "C:\\Users\\Administrator\\Desktop\\MyDroid\\configs\\ipMappingToDNS.txt";
    //dns域名到实体的映射  DNSMappingToEntity.txt
    public static String DNSToEntity = "C:\\Users\\Administrator\\Desktop\\MyDroid\\configs\\DNSMappingToEntity.txt";

    public static String firstParty ;
    public static Set<String> missingThirdParty = new HashSet<>();

    public static void main(String[] args) throws IOException, XmlPullParserException {
        long start = System.currentTimeMillis();
        //初始化ontology和mapping
        EntityOntologyMap.initEntity(EntityOntology);
        PrivacyOntologyMap.initPrivacy(privacyTOOntology);
        ipMappingToDNS.initIp(IPToDNS);
        urlMappingToEntity.init(DNSToEntity);
        apiMappingToPrivacy.initApi(apiTOPrivacy);

        //将隐私策略的分析结果转化成规范格式
        List<String[]> policyResults =  modifyPolicyResults.modifiedPolicyResults(privacyPolicyResults);

        //污点分析所需的配置
        String[] config = new String[]{apkPath,jarsPath,androidCallbackPath,sourceAndSinkPath,easyTaintWrapperSource};

        CallGraph callGraph = infoflowResult.getCallGraph(config);
        firstParty = apkMappingToEntity.changeToEntity(apkPath);

        List<String[]> formedResults = new LinkedList<>();
        List<String[]> sinksToEntity = new LinkedList<>();
        boolean flag = true;
        try {
            List<String[]> res = infoflowResult.taintAnalysis(config);
            List<String[]> sinksToEntity1 = modifyFlowResults.findThirdPartyName(res,callGraph);
            sinksToEntity = sinksToEntity1;
            modifyFlowResults.union(config,sinksToEntity1);
            List<String[]> formedResults1 = modifyFlowResults.modifiedFlowResults(sinksToEntity1,firstParty);
            formedResults = formedResults1;
        }catch (Exception e){
            flag = false;
            List<String[]> res = tool.other.main.sootAnalysis(config);
        }

        if(flag){
            System.out.println("**************************");
            System.out.println("静态分析结果：");
            Map<String,Set<String>> results = modifyFlowResults.modifyResultStructure(formedResults);
            Iterator<Map.Entry<String, Set<String>>> iterator = results.entrySet().iterator();
            while (iterator.hasNext()){
                Map.Entry<String, Set<String>> entry = iterator.next();
                System.out.print(entry.getKey()+" : ");
                for(String data : entry.getValue()){
                    if(data.contains("<")||data.contains("(")){
                    }else {
                        System.out.print(data+" , ");
                    }
                }
                System.out.println();
            }
            System.out.println("**************************");
        }


        long end = System.currentTimeMillis();
        long time = end-start;

        List<String[]> flowResults = modifyFlowResults.modifiedFlowResults(sinksToEntity,firstParty);
        List<String[]> appResults = enhance.modify(flowResults);
            ConsistencyAnalysisResult result = ConsistencyAnalysis.consistencyAnalysis(appResults,policyResults);
            result.outputInconsistentResults(result);

    }




}


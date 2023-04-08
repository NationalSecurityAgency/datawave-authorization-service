package datawave.security.authorization;

import java.util.Collection;
import java.util.List;
import java.util.function.Function;

public interface ProxiedUserDetails {
    
    Collection<? extends DatawaveUser> getProxiedUsers();
    
    String getName();
    
    DatawaveUser getPrimaryUser();
    
    Collection<? extends Collection<String>> getAuthorizations();
    
    String[] getDNs();
    
    String getShortName();
    
    List<String> getProxyServers();
    
    ProxiedUserDetails newInstance(List<DatawaveUser> proxiedUsers);
}

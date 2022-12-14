package datawave.security.authorization;

import java.util.Collection;
import java.util.List;

public interface ProxiedDatawaveUser {
    
    Collection<? extends DatawaveUser> getProxiedUsers();
    
    DatawaveUser getPrimaryUser();
    
    Collection<? extends Collection<String>> getAuthorizations();
    
    String[] getDNs();
    
    String getShortName();
    
    List<String> getProxyServers();
}

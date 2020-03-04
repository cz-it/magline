# magline
![logo](logo/magline_m_big_128.png)

Long connection framework

## Workflow
![workflow](doc/image/magline_workflow.png)

When a client connect to magline. It must send L1 then L2 CMD on order before comunication 
with other business logic moudlues. And if L1 or L2 return an error, magline will return an error message to client and broker the connection.


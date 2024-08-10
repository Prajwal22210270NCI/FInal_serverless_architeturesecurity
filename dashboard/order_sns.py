# from logging import Logger
# from venv import logger
# import boto3, json
# from botocore.exceptions import ClientError
# from django.core.mail import send_mail

# def send_order_email(user_email):
#     sns_client = boto3.client('sns', region_name='eu-west-1')
#     topic_arn = 'arn:aws:sns:eu-west-1:745985292292:order_placed'
#     message = {
#         'Subject': 'Order Confirmation',
#         'Message': f'User has placed order successfully.'
#     }
#     sns_client.publish(TopicArn=topic_arn, Message=json.dumps(message))

#     send_mail(
#         'Order Confirmation',
#         f'User has placed order successfully.',
#         'patil.n.priyal@gmail.com',
#         [user_email,]
#     )

#     def subscribe(topic_arn, email, user_email):
        
#         try:
#             subscription = topic_arn.subscribe(
#                 Protocol=email, Endpoint=user_email, ReturnSubscriptionArn=True
#             )
#             Logger.info("Subscribed %s %s to topic %s.", email, user_email, topic_arn.arn)
#         except ClientError:
#             logger.exception(
#                 "Couldn't subscribe %s %s to topic %s.", email, user_email, topic_arn.arn
#             )
#             raise
#         else:
#             return subscription

def map_user(user):
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['admin'] = user.admin
    return user_data
